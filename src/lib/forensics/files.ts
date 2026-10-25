import { createHash } from "node:crypto";
import { unzipSync } from "fflate";

import { extractUrls } from "@/lib/forensics/urls";
import { extractZip } from "@/lib/archive/zip";
import { analyzeBody } from "@/lib/forensics/body";
import type { ImageFindings } from "@/lib/forensics/image";
import { extractVba, type VbaModule } from "@/lib/forensics/vba";

// Port of desas's attachments.py + forensics.py + archives.py + pe_analyzer.py
// without the Python native stack (olefile, oletools, pefile, pdfminer):
// container structure is read directly from the bytes. Where that is a
// heuristic rather than a full parse (macro source inside vbaProject.bin is
// MS-OVBA-compressed), the reason text says so.

export interface ForensicSignals {
  hasMacros: boolean;
  autoExec: boolean;
  obfuscation: boolean;
  envFingerprinting: boolean;
  stagingLogic: boolean;
  hasJs: boolean;
  hasLaunch: boolean;
  embeddedFiles: boolean;
  doubleExtension: boolean;
  polyglot: boolean;
  appendedData: boolean;
  oleAnomaly: boolean;
  xlmMacro: boolean;
  highEntropy: boolean;
  executable: boolean;
  // Password-protected archive: gateways can't scan inside it.
  encryptedArchive: boolean;
  // A QR code that opens a web link ("quishing").
  qrLink: boolean;
  suspiciousCalls: string[];
}

export interface PeInfo {
  machine: string;
  compileTime?: string;
  sections: Array<{ name: string; entropy: number; size: number }>;
  suspiciousImports: string[];
  packed: boolean;
}

export interface AttachmentAnalysis {
  filename: string;
  size: number;
  contentType?: string;
  fileType: string;
  md5: string;
  sha256: string;
  entropy: number;
  risk: "Clean" | "Suspicious" | "High Risk" | "Malicious";
  score: number;
  reasons: string[];
  signals: ForensicSignals;
  techniques: string[];
  urls: string[];
  pe?: PeInfo;
  archiveEntries?: Array<{ name: string; size: number; encrypted: boolean }>;
  // Whether a password opened the encrypted members (never the password).
  archiveUnlocked?: boolean;
  // Recovered VBA source, per module (trimmed for storage).
  macros?: Array<{ name: string; code: string }>;
  // QR codes and OCR text, for image attachments.
  image?: { width: number; height: number; text: string; qr: string[]; error?: string };
  children?: AttachmentAnalysis[];
}

const RISKY_EXT = [".exe", ".scr", ".com", ".pif", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".ps1", ".jar", ".lnk", ".msi", ".iso", ".img", ".dll", ".cpl"];
const SCRIPT_EXT = [".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".hta", ".html", ".htm", ".wsf"];
const SUSPICIOUS_APIS = [
  "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess",
  "SetThreadContext", "ResumeThread", "NtUnmapViewOfSection", "WinExec", "ShellExecuteA", "ShellExecuteW",
  "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW", "InternetReadFile", "IsDebuggerPresent",
  "GetAsyncKeyState", "SetWindowsHookExA", "CryptEncrypt",
];

const ext = (name: string) => {
  const m = name.toLowerCase().match(/\.[a-z0-9]{1,5}$/);
  return m ? m[0] : "";
};

export function shannonEntropy(data: Uint8Array): number {
  if (data.length === 0) return 0;
  const counts = new Array<number>(256).fill(0);
  for (const b of data) counts[b]++;
  let h = 0;
  for (const c of counts) {
    if (!c) continue;
    const p = c / data.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function latin1(data: Uint8Array) {
  return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("latin1");
}

function indexOfBytes(haystack: Uint8Array, needle: Uint8Array, from = 0): number {
  return Buffer.from(haystack.buffer, haystack.byteOffset, haystack.byteLength).indexOf(Buffer.from(needle), from);
}

const utf16 = (s: string) => new Uint8Array(Buffer.from(s, "utf16le"));

export function detectFileType(data: Uint8Array): string {
  const b = data;
  if (b[0] === 0x4d && b[1] === 0x5a) return "pe";
  if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return "elf";
  if (b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46) return "pdf";
  if (b[0] === 0xd0 && b[1] === 0xcf && b[2] === 0x11 && b[3] === 0xe0) return "ole";
  if (b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) return "zip";
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "jpeg";
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "png";
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) return "gif";
  if (b[0] === 0x52 && b[1] === 0x61 && b[2] === 0x72 && b[3] === 0x21) return "rar";
  if (b[0] === 0x37 && b[1] === 0x7a && b[2] === 0xbc && b[3] === 0xaf) return "7z";
  // ISO 9660 "CD001" at sector 16
  if (latin1(b.subarray(0x8001, 0x8006)) === "CD001") return "iso";
  const head = latin1(b.subarray(0, 512)).toLowerCase();
  if (/<html|<!doctype html|<script/.test(head)) return "html";
  if (/^[\x09\x0a\x0d\x20-\x7e]*$/.test(latin1(b.subarray(0, 512)))) return "text";
  return "binary";
}

// --- ZIP -------------------------------------------------------------------

export interface ZipEntry {
  name: string;
  size: number;
  compressedSize: number;
  encrypted: boolean;
}

// Reads the central directory directly so encrypted members (which a
// decompressor would reject) are still listed and flagged.
export function listZip(data: Uint8Array): ZipEntry[] {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let eocd = -1;
  for (let i = data.length - 22; i >= Math.max(0, data.length - 65557); i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return [];
  const count = view.getUint16(eocd + 10, true);
  let offset = view.getUint32(eocd + 16, true);
  const entries: ZipEntry[] = [];
  for (let i = 0; i < count && offset + 46 <= data.length; i++) {
    if (view.getUint32(offset, true) !== 0x02014b50) break;
    const flags = view.getUint16(offset + 8, true);
    const compressedSize = view.getUint32(offset + 20, true);
    const size = view.getUint32(offset + 24, true);
    const nameLen = view.getUint16(offset + 28, true);
    const extraLen = view.getUint16(offset + 30, true);
    const commentLen = view.getUint16(offset + 32, true);
    const name = Buffer.from(data.subarray(offset + 46, offset + 46 + nameLen)).toString("utf8");
    entries.push({ name, size, compressedSize, encrypted: (flags & 0x1) === 1 });
    offset += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function readZipMembers(data: Uint8Array, names: (name: string) => boolean): Record<string, Uint8Array> {
  try {
    return unzipSync(data, { filter: (f) => names(f.name) && f.originalSize < 50 * 1024 * 1024 });
  } catch {
    return {};
  }
}

// --- format-specific analyzers ---------------------------------------------

// desas forensics.vba_semantic_analysis, applied to whatever macro text is
// recoverable.
export function vbaSemantics(code: string) {
  const low = code.toLowerCase();
  const calls: Record<string, string> = {
    "wscript.shell": "WScript.Shell interaction",
    shell: "Shell execution",
    powershell: "PowerShell invocation",
    createobject: "Dynamic object creation",
    "adodb.stream": "File stream writes (dropper logic)",
    xmlhttp: "Network download (XMLHTTP)",
    winhttprequest: "Network download (WinHTTP)",
    urldownloadtofile: "Network download (URLDownloadToFile)",
    "shell.application": "Shell.Application execution",
  };
  return {
    autoExec: /auto_?open|workbook_open|document_open|autoexec|autoclose|document_close/.test(low),
    envFingerprinting: /environ\(|computername|getobject\("winmgmts:|win32_process|username/.test(low),
    stagingLogic: ["split(", "join(", "replace(", "chr(", "strconv(", "strreverse"].filter((k) => low.includes(k)).length >= 2,
    obfuscation: (low.match(/chr\(/g) ?? []).length > 10 || low.includes("strreverse"),
    suspiciousCalls: Object.entries(calls).filter(([k]) => low.includes(k)).map(([, v]) => v),
  };
}

// desas forensics.obfuscation_heuristics for scripts.
export function obfuscationScore(text: string): number {
  if (!text) return 0;
  let score = 0;
  const low = text.toLowerCase();
  if (/chr\(\d+\)|fromcharcode/.test(low)) score += 20;
  if ((text.match(/\+/g) ?? []).length > 50 || (text.match(/&/g) ?? []).length > 50) score += 15;
  if (/[A-Za-z0-9+/=]{80,}/.test(text)) score += 25;
  if (/\beval\s*\(|\bexecute\s*\(|invoke-expression|\biex\b/.test(low)) score += 15;
  if (text.length > 100) {
    const letters = text.replace(/[^A-Za-z]/g, "");
    const upper = letters.replace(/[^A-Z]/g, "").length;
    const ratio = letters.length ? upper / letters.length : 0;
    if (ratio > 0.3 && ratio < 0.7) score += 10;
  }
  return score;
}

function analyzePdf(data: Uint8Array) {
  const raw = latin1(data);
  const low = raw.toLowerCase();
  const tags: string[] = [];
  const has = (re: RegExp, label: string) => {
    if (re.test(low)) tags.push(label);
  };
  has(/\/javascript\b|\/js\s*[(<\/]/, "JavaScript");
  has(/\/launch\b/, "Launch action");
  has(/\/embeddedfile\b/, "Embedded file");
  has(/\/openaction\b/, "Auto-open action");
  has(/\/aa\s*<</, "Additional actions (auto-trigger)");
  has(/\/richmedia\b/, "RichMedia (Flash)");
  const urls = [...raw.matchAll(/\/URI\s*\(([^)]+)\)/g)].map((m) => m[1]);
  return {
    tags,
    urls,
    encrypted: /\/encrypt\b/.test(low),
    evasion: low.includes("/objstm") && !low.includes("/xref") && !low.includes("startxref"),
  };
}

const MACHINES: Record<number, string> = { 0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64" };

export function analyzePe(data: Uint8Array): PeInfo | undefined {
  if (data.length < 0x40 || data[0] !== 0x4d || data[1] !== 0x5a) return undefined;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const peOffset = view.getUint32(0x3c, true);
  if (peOffset + 24 > data.length || view.getUint32(peOffset, true) !== 0x00004550) return undefined;
  const machine = view.getUint16(peOffset + 4, true);
  const sectionCount = view.getUint16(peOffset + 6, true);
  const timestamp = view.getUint32(peOffset + 8, true);
  const optionalSize = view.getUint16(peOffset + 20, true);
  const sectionTable = peOffset + 24 + optionalSize;

  const sections: PeInfo["sections"] = [];
  for (let i = 0; i < Math.min(sectionCount, 96); i++) {
    const off = sectionTable + i * 40;
    if (off + 40 > data.length) break;
    const name = latin1(data.subarray(off, off + 8)).replace(/\0+$/, "");
    const rawSize = view.getUint32(off + 16, true);
    const rawPtr = view.getUint32(off + 20, true);
    const bytes = data.subarray(rawPtr, Math.min(data.length, rawPtr + rawSize));
    sections.push({ name, size: rawSize, entropy: Math.round(shannonEntropy(bytes) * 100) / 100 });
  }

  // Import names are stored as ASCII in the hint/name table; a string scan
  // finds them without walking the import directory.
  const text = latin1(data);
  const suspiciousImports = SUSPICIOUS_APIS.filter((api) => text.includes(`${api}\0`));
  const packed =
    sections.some((s) => (s.name === ".text" || s.name === "CODE") && s.entropy > 7.1) ||
    sections.some((s) => /^(UPX\d|\.aspack|\.petite|\.themida|\.vmp\d)/i.test(s.name));

  return {
    machine: MACHINES[machine] ?? `0x${machine.toString(16)}`,
    compileTime: timestamp ? new Date(timestamp * 1000).toISOString() : undefined,
    sections,
    suspiciousImports,
    packed,
  };
}

const OLE_STREAMS: Array<[string, string, keyof ForensicSignals | null]> = [
  ["_VBA_PROJECT", "VBA macro project", "hasMacros"],
  ["Macros", "Macros storage", "hasMacros"],
  ["Equation Native", "Equation Editor object (CVE-2017-11882 exploit vector)", "oleAnomaly"],
  ["Ole10Native", "Embedded native object (often a packaged executable)", "oleAnomaly"],
  ["ObjectPool", "Nested OLE objects (evasion)", "oleAnomaly"],
  ["Package", "Embedded OLE package", "oleAnomaly"],
];

const TECHNIQUE_FOR_SIGNAL: Partial<Record<keyof ForensicSignals, string>> = {
  autoExec: "T1204.002",
  obfuscation: "T1027",
  envFingerprinting: "T1497",
  stagingLogic: "T1059",
  hasMacros: "T1059.005",
  hasJs: "T1059.007",
  doubleExtension: "T1036.007",
  polyglot: "T1027.001",
  appendedData: "T1027.001",
  oleAnomaly: "T1204.002",
  xlmMacro: "T1059",
  executable: "T1204.002",
  encryptedArchive: "T1027.013",
  qrLink: "T1566.002",
};

// Techniques the forensics module can emit (attachment signals plus the
// message-level mappings in forensics/service.ts) — feeds the coverage matrix.
export const FORENSICS_RULE_TECHNIQUES: Array<{ rule: string; techniques: string[] }> = [
  ...Object.entries(TECHNIQUE_FOR_SIGNAL).map(([signal, t]) => ({ rule: `attachment:${signal}`, techniques: [t!] })),
  { rule: "email:malicious_attachment", techniques: ["T1566.001"] },
  { rule: "email:malicious_link", techniques: ["T1566.002", "T1204.001"] },
  { rule: "email:credential_capture", techniques: ["T1598"] },
];

// desas forensics.infer_mitre_techniques.
export function techniquesFor(signals: ForensicSignals): string[] {
  return [...new Set((Object.keys(TECHNIQUE_FOR_SIGNAL) as Array<keyof ForensicSignals>).filter((k) => signals[k] === true).map((k) => TECHNIQUE_FOR_SIGNAL[k]!))].sort();
}

// Folds what an image holds into its attachment analysis: a QR code that
// opens a link scores like a phishing link (the gateway never saw it as
// text), and printed text goes through the same content checks as a body.
export function applyImageFindings(a: AttachmentAnalysis, img: ImageFindings, whitelist?: string[]): AttachmentAnalysis {
  const reasons = [...a.reasons];
  const urls = new Set(a.urls);
  const signals = { ...a.signals };
  let score = a.score;
  for (const payload of img.qr) {
    if (/^https?:\/\//i.test(payload)) {
      signals.qrLink = true;
      score += 25;
      urls.add(payload);
      reasons.push(`QR code opens ${payload}`);
    } else {
      reasons.push(`QR code holds: ${payload.slice(0, 80)}`);
    }
  }
  if (img.text.length >= 20) {
    const body = analyzeBody(img.text, undefined, whitelist);
    score += Math.min(40, body.score);
    reasons.push(...body.reasons.map((r) => `Text in image: ${r}`));
    body.urls.forEach((u) => urls.add(u));
  }
  return {
    ...a,
    score,
    risk: riskFor(score),
    reasons: [...new Set(reasons)],
    urls: [...urls],
    signals,
    techniques: techniquesFor(signals),
    image: { width: img.width, height: img.height, text: img.text.slice(0, 2000), qr: img.qr, error: img.error },
  };
}

export function riskFor(score: number): AttachmentAnalysis["risk"] {
  if (score >= 70) return "Malicious";
  if (score >= 40) return "High Risk";
  if (score >= 15) return "Suspicious";
  return "Clean";
}

export interface FileOptions {
  // Tried on encrypted archives: the analyst's passwords first, then any
  // quoted in the message that carried the file.
  passwords?: string[];
  quotedPasswords?: string[];
}

export function analyzeFile(filename: string, data: Uint8Array, contentType?: string, depth = 0, opts: FileOptions = {}): AttachmentAnalysis {
  const reasons: string[] = [];
  let score = 0;
  const signals: ForensicSignals = {
    hasMacros: false, autoExec: false, obfuscation: false, envFingerprinting: false, stagingLogic: false,
    hasJs: false, hasLaunch: false, embeddedFiles: false, doubleExtension: false, polyglot: false,
    appendedData: false, oleAnomaly: false, xlmMacro: false, highEntropy: false, executable: false, encryptedArchive: false, qrLink: false, suspiciousCalls: [],
  };
  const lowerName = filename.toLowerCase();
  const extension = ext(lowerName);
  const fileType = detectFileType(data);
  const urls = new Set<string>();
  const result: Partial<AttachmentAnalysis> = {};

  // --- name-based checks
  if (RISKY_EXT.includes(extension)) {
    score += 20;
    signals.executable = [".exe", ".scr", ".com", ".pif", ".dll", ".cpl", ".msi"].includes(extension);
    reasons.push(`Executable / script attachment type: ${extension}`);
  }
  if (/\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|rtf|csv)\.(exe|scr|js|jse|vbs|vbe|bat|cmd|hta|ps1|lnk|com)$/i.test(lowerName)) {
    score += 20;
    signals.doubleExtension = true;
    reasons.push(`Double extension masquerading: ${filename}`);
  }

  // --- extension vs content mismatch (masquerading)
  const officeExt = [".doc", ".xls", ".ppt", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"];
  if (fileType === "pe" && !RISKY_EXT.includes(extension)) {
    score += 40;
    signals.executable = true;
    signals.polyglot = true;
    reasons.push(`Windows executable disguised as ${extension || "an extensionless file"}`);
  }

  // --- embedded / appended payloads (tightened polyglot check)
  if (fileType !== "pe" && fileType !== "zip" && fileType !== "ole") {
    const dosStub = indexOfBytes(data, new TextEncoder().encode("This program cannot be run in DOS mode"));
    if (dosStub > 64) {
      score += 25;
      signals.polyglot = true;
      reasons.push(`Embedded Windows executable inside ${fileType.toUpperCase()} content (offset ${dosStub})`);
    }
  }
  if (fileType === "jpeg" || fileType === "png") {
    const eof = fileType === "jpeg" ? Buffer.from([0xff, 0xd9]) : Buffer.from("IEND");
    const buf = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    const end = buf.lastIndexOf(eof);
    const tail = end >= 0 ? buf.subarray(end + eof.length + (fileType === "png" ? 4 : 0)) : Buffer.alloc(0);
    if (tail.length > 16 && (tail.includes(Buffer.from("MZ")) || tail.includes(Buffer.from([0x50, 0x4b, 0x03, 0x04])) || tail.toString("latin1").toLowerCase().includes("powershell"))) {
      score += 25;
      signals.appendedData = true;
      reasons.push("Payload appended after the image end-of-file marker");
    }
  }

  // --- PE
  if (fileType === "pe") {
    const pe = analyzePe(data);
    if (pe) {
      result.pe = pe;
      signals.executable = true;
      if (pe.packed) {
        score += 40;
        signals.obfuscation = true;
        signals.highEntropy = true;
        reasons.push(`Packed / encrypted code section (${pe.sections.map((s) => `${s.name}:${s.entropy}`).join(", ")})`);
      }
      if (pe.suspiciousImports.length > 2) {
        score += Math.min(pe.suspiciousImports.length * 10, 50);
        signals.suspiciousCalls.push(...pe.suspiciousImports);
        reasons.push(`Suspicious Windows APIs referenced: ${pe.suspiciousImports.slice(0, 6).join(", ")}`);
      }
    }
  }

  // --- PDF
  if (fileType === "pdf") {
    const pdf = analyzePdf(data);
    pdf.urls.forEach((u) => urls.add(u));
    if (pdf.tags.includes("JavaScript") || pdf.tags.includes("Launch action")) {
      score += 30;
      signals.hasJs = pdf.tags.includes("JavaScript");
      signals.hasLaunch = pdf.tags.includes("Launch action");
      reasons.push(`Active content in PDF: ${pdf.tags.join(", ")}`);
    } else if (pdf.tags.length) {
      score += 10;
      reasons.push(`PDF auto-actions: ${pdf.tags.join(", ")}`);
    }
    if (pdf.tags.includes("Embedded file")) signals.embeddedFiles = true;
    if (pdf.evasion) {
      score += 20;
      signals.obfuscation = true;
      reasons.push("PDF object streams without a cross-reference table (parser evasion)");
    }
    if (pdf.encrypted) reasons.push("PDF is encrypted (content could not be fully inspected)");
  }

  // --- OLE (legacy Office)
  if (fileType === "ole") {
    for (const [stream, label, signal] of OLE_STREAMS) {
      if (indexOfBytes(data, utf16(stream)) >= 0) {
        if (signal === "hasMacros") {
          if (!signals.hasMacros) {
            signals.hasMacros = true;
            score += 30;
            reasons.push(`Macros present in ${filename} (${label})`);
          }
        } else if (signal) {
          signals.oleAnomaly = true;
          score += 20;
          reasons.push(label);
        }
      }
    }
    if (signals.hasMacros) macroSource(extractVba(data), data);
    if ([".xls", ".xlsb"].includes(extension)) checkXlm(latin1(data));
  }

  // --- ZIP (OOXML or archive)
  if (fileType === "zip") {
    const entries = listZip(data);
    const isOoxml = entries.some((e) => e.name === "[Content_Types].xml");
    if (isOoxml) {
      const macroBin = entries.find((e) => /(^|\/)vbaProject\.bin$/i.test(e.name));
      if (macroBin) {
        signals.hasMacros = true;
        score += 30;
        reasons.push(`Macros present in ${filename} (${macroBin.name})`);
        if (!extension.endsWith("m")) {
          score += 15;
          reasons.push(`Macro-enabled content inside a ${extension || "file"} that shouldn't carry macros`);
        }
        const members = readZipMembers(data, (n) => n === macroBin.name);
        const bin = members[macroBin.name];
        if (bin) macroSource(extractVba(bin), bin);
      }
      if (entries.some((e) => /^xl\/macrosheets\//i.test(e.name))) {
        signals.xlmMacro = true;
        score += 30;
        reasons.push("Excel 4.0 (XLM) macro sheet present");
      }
      if (entries.some((e) => /oleObject\d*\.bin$/i.test(e.name))) {
        signals.oleAnomaly = true;
        score += 20;
        reasons.push("Embedded OLE object in Office document");
      }
      const rels = readZipMembers(data, (n) => n.endsWith(".rels"));
      for (const xml of Object.values(rels)) {
        const s = Buffer.from(xml).toString("utf8");
        for (const m of s.matchAll(/Target="(https?:[^"]+)"[^>]*TargetMode="External"/gi)) urls.add(m[1].replace(/&amp;/g, "&"));
        if (/attachedTemplate[^>]+Target="https?:/i.test(s)) {
          score += 30;
          signals.oleAnomaly = true;
          reasons.push("Remote template injection (attachedTemplate points at an external URL)");
        }
      }
    } else {
      result.archiveEntries = entries.map((e) => ({ name: e.name, size: e.size, encrypted: e.encrypted }));
      for (const e of entries) {
        const eExt = ext(e.name);
        if (RISKY_EXT.includes(eExt)) {
          score += 30;
          reasons.push(`Archive contains executable/script: ${e.name}`);
        }
        if (/\.[a-z0-9]{2,4}\.(exe|js|vbs|bat|cmd|scr|lnk)$/i.test(e.name)) {
          score += 20;
          signals.doubleExtension = true;
          reasons.push(`Archive member masquerades with a double extension: ${e.name}`);
        }
        if (e.encrypted) {
          score += 15;
          signals.encryptedArchive = true;
          reasons.push(`Password-protected archive member (evades scanning): ${e.name}`);
        }
      }
      if (depth === 0) {
        let members: Record<string, Uint8Array>;
        if (signals.encryptedArchive) {
          const opened = extractZip(data, { passwords: [...(opts.passwords ?? []), ...(opts.quotedPasswords ?? [])], maxMemberBytes: 50 * 1024 * 1024 });
          members = opened.files;
          if (opened.passwordUsed && opts.quotedPasswords?.includes(opened.passwordUsed) && !opts.passwords?.includes(opened.passwordUsed)) {
            score += 20;
            reasons.push("Opened with a password quoted in the message — the usual way to slip a payload past gateway scanning");
          } else if (opened.passwordUsed) {
            reasons.push("Opened with the password supplied for analysis");
          }
          if (opened.locked.length) reasons.push(`${opened.locked.length} encrypted member(s) not opened — supply the archive password to analyze them`);
          result.archiveUnlocked = !!opened.passwordUsed;
        } else {
          members = readZipMembers(data, (n) => !n.endsWith("/"));
        }
        result.children = Object.entries(members).slice(0, 25).map(([name, bytes]) => analyzeFile(name, bytes, undefined, depth + 1));
        for (const child of result.children) {
          if (child.score > 0) {
            score += Math.round(child.score / 2);
            child.urls.forEach((u) => urls.add(u));
          }
        }
      }
    }
  }

  // --- scripts / HTML / text
  if (fileType === "html" || fileType === "text" || SCRIPT_EXT.includes(extension)) {
    const text = Buffer.from(data.subarray(0, 2 * 1024 * 1024)).toString("utf8");
    extractUrls(text).forEach((u) => urls.add(u));
    if (SCRIPT_EXT.includes(extension) || fileType === "html") {
      const obf = obfuscationScore(text);
      if (obf > 20) {
        score += obf;
        signals.obfuscation = true;
        reasons.push(`Heavily obfuscated script content (score ${obf})`);
      }
      if (/<script/i.test(text) || [".js", ".jse", ".hta"].includes(extension)) signals.hasJs = true;
      const vba = vbaSemantics(text);
      if (vba.suspiciousCalls.length) {
        score += 10 * Math.min(3, vba.suspiciousCalls.length);
        signals.suspiciousCalls.push(...vba.suspiciousCalls);
        reasons.push(`Script uses: ${vba.suspiciousCalls.join(", ")}`);
      }
    }
    if (/\b(callback|billing department|subscription|renewal|order confirmed|pending payment)\b/i.test(text) && /\+?\d[\d\s().-]{9,}\d/.test(text)) {
      score += 15;
      reasons.push("Callback-phishing (TOAD) language with a phone number");
    }
  }

  // --- entropy (skip formats that are compressed by design)
  const entropy = shannonEntropy(data);
  if (entropy > 7.2 && !["zip", "jpeg", "png", "gif", "rar", "7z", "pdf"].includes(fileType)) {
    signals.highEntropy = true;
    score += 15;
    reasons.push(`High entropy (${entropy.toFixed(2)} bits/byte) — possible packed or encrypted payload`);
  }

  if (fileType === "iso" || [".iso", ".img", ".vhd", ".vhdx"].includes(extension)) {
    score += 20;
    reasons.push("Disk image attachment (common Mark-of-the-Web bypass)");
  }

  const md5 = createHash("md5").update(data).digest("hex");
  const sha256 = createHash("sha256").update(data).digest("hex");
  const techniques = techniquesFor(signals);
  return {
    filename,
    size: data.byteLength,
    contentType,
    fileType: officeExt.includes(extension) && (fileType === "zip" || fileType === "ole") ? `office (${fileType === "zip" ? "OOXML" : "OLE"})` : fileType,
    md5,
    sha256,
    entropy: Math.round(entropy * 100) / 100,
    risk: riskFor(score),
    score,
    reasons: [...new Set(reasons)],
    signals: { ...signals, suspiciousCalls: [...new Set(signals.suspiciousCalls)] },
    techniques,
    urls: [...urls],
    ...result,
  };

  // Analyze the recovered source; only if none could be recovered, fall back
  // to scanning the container bytes (where compression can split keywords).
  function macroSource(modules: VbaModule[], container: Uint8Array) {
    if (!modules.length) {
      applyVba(vbaSemantics(latin1(container)), " (keyword scan of the compressed macro container — source could not be recovered)");
      return;
    }
    const code = modules.map((m) => m.code).join("\n");
    reasons.push(`Macro source recovered: ${modules.length} module${modules.length === 1 ? "" : "s"} (${modules.map((m) => m.name).join(", ")})`);
    applyVba(vbaSemantics(code));
    extractUrls(code).forEach((u) => urls.add(u));
    result.macros = modules.slice(0, 20).map((m) => ({ name: m.name, code: m.code.slice(0, 20_000) }));
  }

  function applyVba(vba: ReturnType<typeof vbaSemantics>, note = "") {
    if (vba.autoExec) {
      score += 25;
      signals.autoExec = true;
      reasons.push(`Auto-execution entry point in macro${note}`);
    }
    if (vba.obfuscation) {
      score += 20;
      signals.obfuscation = true;
      reasons.push(`Obfuscated macro code${note}`);
    }
    if (vba.stagingLogic) {
      score += 20;
      signals.stagingLogic = true;
      reasons.push(`Payload staging logic in macro${note}`);
    }
    if (vba.envFingerprinting) {
      signals.envFingerprinting = true;
      reasons.push(`Macro fingerprints the environment (sandbox evasion)${note}`);
    }
    if (vba.suspiciousCalls.length) {
      score += 10 * Math.min(3, vba.suspiciousCalls.length);
      signals.suspiciousCalls.push(...vba.suspiciousCalls);
      reasons.push(`Macro uses: ${vba.suspiciousCalls.join(", ")}${note}`);
    }
  }

  function checkXlm(raw: string) {
    const ops = ["EXEC(", "REGISTER(", "CALL(", "HALT(", "FORMULA(", "WINDOW.HIDE", "WORKBOOK.HIDE", "GET.WORKSPACE"].filter((op) => raw.includes(op));
    if (ops.length >= 2) {
      signals.xlmMacro = true;
      score += 30;
      reasons.push(`Excel 4.0 (XLM) macro functions: ${ops.join(", ")}`);
    }
  }
}
