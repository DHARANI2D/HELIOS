import * as CFB from "cfb";
import type { CFB$Container } from "cfb";
import JSZip from "jszip";

// Ported from desas's analyzer/forensics.py — pure byte/string forensic
// heuristics, portable without any native dependency once the
// OLE-container listing (cfb, replacing Python's olefile) and ZIP
// listing (jszip, replacing Python's built-in zipfile) are swapped in.

export function shannonEntropy(data: Buffer): number {
  if (data.length === 0) return 0;
  const freq = new Map<number, number>();
  for (const byte of data) freq.set(byte, (freq.get(byte) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / data.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function obfuscationHeuristics(data: string): number {
  if (!data) return 0;
  let score = 0;
  const low = data.toLowerCase();

  if (/chr\(\d+\)/.test(low)) score += 20;
  if ((data.match(/\+/g)?.length ?? 0) > 50 || (data.match(/&/g)?.length ?? 0) > 50) score += 15;
  if (/[A-Za-z0-9+/=]{80,}/.test(data)) score += 25;

  if (data.length > 100) {
    const alphas = [...data].filter((c) => /[a-zA-Z]/.test(c));
    if (alphas.length > 0) {
      const upperCount = alphas.filter((c) => c === c.toUpperCase() && c !== c.toLowerCase()).length;
      const ratio = upperCount / alphas.length;
      if (ratio > 0.3 && ratio < 0.7) score += 10;
    }
  }

  return score;
}

export interface VbaSemanticResult {
  autoExec: boolean;
  envFingerprinting: boolean;
  stagingLogic: boolean;
  obfuscation: boolean;
  suspiciousCalls: string[];
}

const AUTO_EXEC_MARKERS = ["auto_open", "workbook_open", "document_open", "auto_exec", "autoopen"];
const ENV_CALL_MARKERS = ["environ", "username", "computername", 'getobject("winmgmts:', "win32_process"];
const STAGING_MARKERS = ["split(", "join(", "replace(", "chr(", "strconv(", "getbyte"];
const SUSPICIOUS_CALL_MAP: Record<string, string> = {
  shell: "Shell execution",
  "wscript.shell": "WScript interaction",
  powershell: "PowerShell invocation",
  createobject: "Dynamic object creation",
  "adodb.stream": "File system stream (dropper logic)",
  xmlhttp: "Network download (XMLHTTP)",
  winhttprequest: "Network download (WinHTTP)",
  urlretrieve: "Network download",
  base64: "Encoded payload",
};

export function vbaSemanticAnalysis(vbaCode: string): VbaSemanticResult {
  const result: VbaSemanticResult = {
    autoExec: false,
    envFingerprinting: false,
    stagingLogic: false,
    obfuscation: false,
    suspiciousCalls: [],
  };
  if (!vbaCode) return result;

  const low = vbaCode.toLowerCase();
  result.autoExec = AUTO_EXEC_MARKERS.some((m) => low.includes(m));
  result.envFingerprinting = ENV_CALL_MARKERS.some((m) => low.includes(m));
  result.stagingLogic = STAGING_MARKERS.filter((m) => low.includes(m)).length >= 2;

  for (const [call, desc] of Object.entries(SUSPICIOUS_CALL_MAP)) {
    if (low.includes(call)) result.suspiciousCalls.push(desc);
  }

  result.obfuscation = (low.match(/chr\(/g)?.length ?? 0) > 10 || low.includes("strreverse");
  return result;
}

export interface StructuralAnalysis {
  isArchive: boolean;
  unexpectedFiles: string[];
  structureScore: number;
}

const RISKY_EXTENSIONS = [".exe", ".dll", ".js", ".vbs", ".ps1", ".vbe", ".jse", ".cmd", ".bat"];

export async function structuralAnalysis(content: Buffer): Promise<StructuralAnalysis> {
  const findings: StructuralAnalysis = { isArchive: false, unexpectedFiles: [], structureScore: 0 };

  let zip: JSZip;
  try {
    zip = await JSZip.loadAsync(content);
  } catch {
    return findings;
  }

  findings.isArchive = true;
  for (const filename of Object.keys(zip.files)) {
    const lower = filename.toLowerCase();
    const ext = lower.includes(".") ? `.${lower.split(".").pop()}` : "";

    if (RISKY_EXTENSIONS.includes(ext)) {
      findings.unexpectedFiles.push(filename);
      findings.structureScore += 30;
    }
    if (/\.[a-z0-9]{2,4}\.(exe|js|vbs|bat|cmd)$/.test(lower)) {
      findings.unexpectedFiles.push(`${filename} (potential masquerading)`);
      findings.structureScore += 20;
    }
  }

  return findings;
}

const FILE_SIGNATURES: [Buffer, string][] = [
  [Buffer.from([0x50, 0x4b, 0x03, 0x04]), "ZIP/Office"],
  [Buffer.from("%PDF"), "PDF"],
  [Buffer.from([0xff, 0xd8, 0xff]), "JPEG"],
  [Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), "PNG"],
  [Buffer.from("MZ"), "PE Executable"],
  [Buffer.from("BM"), "BMP"],
  [Buffer.from("GIF8"), "GIF"],
  [Buffer.from([0x7f, 0x45, 0x4c, 0x46]), "ELF Executable"],
];

export function detectPolyglots(content: Buffer): string[] {
  const findings: string[] = [];
  if (content.length < 100) return findings;

  const found = FILE_SIGNATURES.filter(([sig]) => content.includes(sig)).map(([, label]) => label);
  if (found.length > 1) {
    findings.push(`Polyglot indicators: ${found.join(", ")}`);
  }

  const jpegEof = Buffer.from([0xff, 0xd9]);
  const pngEof = Buffer.from("\x00\x00\x00\x00IEND\xaeB\x60\x82", "binary");
  for (const eof of [jpegEof, pngEof]) {
    const eofPos = content.lastIndexOf(eof);
    if (eofPos === -1) continue;
    const dataEnd = eofPos + eof.length;
    if (content.length > dataEnd + 10) {
      const extra = content.subarray(dataEnd);
      if (
        extra.includes(Buffer.from("MZ")) ||
        extra.includes(Buffer.from([0x50, 0x4b, 0x03, 0x04])) ||
        extra.includes(Buffer.from("powershell"))
      ) {
        findings.push("Appended malicious payload detected after image EOF");
      }
    }
  }

  return findings;
}

export interface OleStreamResult {
  riskyStreams: string[];
  oleAnomalies: boolean;
}

const OLE_TARGET_STREAMS: Record<string, string> = {
  mbdg: "Potentially obfuscated shellcode stream",
  package: "Embedded OLE Package (often an EXE)",
  "equation native": "Equation Editor exploit (CVE-2017-11882)",
  ole10native: "Embedded native code/binary",
  objectpool: "Nested OLE objects (evasion)",
};

export function analyzeOleStreams(content: Buffer): OleStreamResult {
  const indicators: OleStreamResult = { riskyStreams: [], oleAnomalies: false };

  let container: CFB$Container;
  try {
    container = CFB.read(content, { type: "buffer" });
  } catch {
    return indicators;
  }

  const streamNames = container.FileIndex.map((e) => e.name.toLowerCase());
  for (const [marker, desc] of Object.entries(OLE_TARGET_STREAMS)) {
    if (streamNames.some((s) => s.includes(marker))) {
      indicators.riskyStreams.push(desc);
      indicators.oleAnomalies = true;
    }
  }

  return indicators;
}

const XLM_PATTERNS = ["EXEC", "REGISTER", "CALL", "HALT", "RUN", "CHAR", "GET.WINDOW", "WINDOW.HIDE", "WORKBOOK.HIDE"];

export function detectXlmMacros(rawContent: Buffer): string[] {
  const asString = rawContent.toString("latin1");
  const found = XLM_PATTERNS.filter((p) => asString.includes(p));
  if (found.length >= 3) {
    return [`Excel 4.0 (XLM) macro pattern detected: ${found.join(", ")}`];
  }
  return [];
}

export interface PdfForensicSignals {
  hasJs: boolean;
  hasLaunch: boolean;
  embeddedFiles: boolean;
  evasionDetected: boolean;
  suspiciousTags: string[];
}

export function pdfForensicSignals(rawContent: Buffer): PdfForensicSignals {
  const signals: PdfForensicSignals = {
    hasJs: false,
    hasLaunch: false,
    embeddedFiles: false,
    evasionDetected: false,
    suspiciousTags: [],
  };

  const raw = rawContent.toString("latin1").toLowerCase();

  if (raw.includes("/javascript") || raw.includes("/js")) signals.hasJs = true;
  if (raw.includes("/launch")) signals.hasLaunch = true;
  if (raw.includes("/embeddedfile")) signals.embeddedFiles = true;
  if (raw.includes("/richtext")) signals.suspiciousTags.push("Rich text content");
  if (raw.includes("/openaction")) signals.suspiciousTags.push("Auto-open action");
  if (raw.includes("/aa")) signals.suspiciousTags.push("Additional action (auto-trigger)");
  if (raw.includes("/objstm") && !raw.includes("/xref")) signals.evasionDetected = true;

  return signals;
}

const MITRE_TECHNIQUE_MAP: Record<string, string> = {
  autoExec: "T1204.002",
  obfuscation: "T1027",
  envFingerprinting: "T1497",
  stagingLogic: "T1059",
  hasMacros: "T1059.005",
  hasJs: "T1059.007",
  doubleExtension: "T1036.007",
  polyglot: "T1027.001",
  oleAnomaly: "T1204.002",
  xlmMacro: "T1059",
  appendedData: "T1027.001",
};

export function inferMitreTechniques(signals: Record<string, boolean>): string[] {
  const techniques = Object.entries(MITRE_TECHNIQUE_MAP)
    .filter(([sig]) => signals[sig])
    .map(([, tech]) => tech);
  return [...new Set(techniques)].sort();
}
