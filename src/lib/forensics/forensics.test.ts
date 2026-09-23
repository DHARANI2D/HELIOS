import { describe, it, expect } from "vitest";

import {
  shannonEntropy,
  obfuscationHeuristics,
  vbaSemanticAnalysis,
  detectPolyglots,
  detectXlmMacros,
  pdfForensicSignals,
  inferMitreTechniques,
} from "./forensics";

describe("shannonEntropy", () => {
  it("returns 0 for empty input", () => {
    expect(shannonEntropy(Buffer.alloc(0))).toBe(0);
  });

  it("returns 0 for a buffer of all identical bytes (no uncertainty)", () => {
    expect(shannonEntropy(Buffer.alloc(1000, 0x41))).toBe(0);
  });

  it("returns close to 8 for high-entropy random bytes", () => {
    const random = Buffer.from(Array.from({ length: 4096 }, () => Math.floor(Math.random() * 256)));
    expect(shannonEntropy(random)).toBeGreaterThan(7.9);
  });

  it("returns a low but nonzero value for repetitive text", () => {
    const text = Buffer.from("the quick brown fox ".repeat(50));
    const entropy = shannonEntropy(text);
    expect(entropy).toBeGreaterThan(0);
    expect(entropy).toBeLessThan(5);
  });
});

describe("obfuscationHeuristics", () => {
  it("scores 0 for empty input", () => {
    expect(obfuscationHeuristics("")).toBe(0);
  });

  it("flags Chr() character-code usage", () => {
    expect(obfuscationHeuristics("x = Chr(65) & Chr(66)")).toBeGreaterThanOrEqual(20);
  });

  it("flags a long base64-looking blob", () => {
    const blob = "A".repeat(90);
    expect(obfuscationHeuristics(blob)).toBeGreaterThanOrEqual(25);
  });

  it("does not flag plain prose", () => {
    expect(obfuscationHeuristics("This is a perfectly normal sentence.")).toBe(0);
  });
});

describe("vbaSemanticAnalysis", () => {
  it("returns all-false indicators for empty input", () => {
    const result = vbaSemanticAnalysis("");
    expect(result.autoExec).toBe(false);
    expect(result.suspiciousCalls).toHaveLength(0);
  });

  it("detects auto-exec triggers", () => {
    expect(vbaSemanticAnalysis("Sub Auto_Open()\nEnd Sub").autoExec).toBe(true);
  });

  it("detects suspicious calls (shell, powershell, dropper logic)", () => {
    const code = 'Shell "powershell.exe -enc AAAA"\nSet f = CreateObject("ADODB.Stream")';
    const result = vbaSemanticAnalysis(code);
    expect(result.suspiciousCalls).toContain("Shell execution");
    expect(result.suspiciousCalls).toContain("PowerShell invocation");
    expect(result.suspiciousCalls).toContain("File system stream (dropper logic)");
  });

  it("detects environment fingerprinting", () => {
    expect(vbaSemanticAnalysis("x = Environ(\"USERNAME\")").envFingerprinting).toBe(true);
  });

  it("does not flag benign VBA", () => {
    const result = vbaSemanticAnalysis("Sub Main()\n  MsgBox \"Hello\"\nEnd Sub");
    expect(result.autoExec).toBe(false);
    expect(result.envFingerprinting).toBe(false);
    expect(result.suspiciousCalls).toHaveLength(0);
  });
});

describe("detectPolyglots", () => {
  it("returns nothing for a buffer too small to matter", () => {
    expect(detectPolyglots(Buffer.from("short"))).toHaveLength(0);
  });

  it("flags a buffer containing two distinct file signatures", () => {
    const padding = Buffer.alloc(200, 0x00);
    const zipSig = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
    const peSig = Buffer.from("MZ");
    const content = Buffer.concat([zipSig, padding, peSig, padding]);
    const findings = detectPolyglots(content);
    expect(findings.some((f) => f.includes("Polyglot"))).toBe(true);
  });

  it("does not flag a clean single-signature file", () => {
    const content = Buffer.concat([Buffer.from("%PDF-1.4"), Buffer.alloc(200, 0x20)]);
    expect(detectPolyglots(content)).toHaveLength(0);
  });

  it("flags appended data after a PNG EOF marker", () => {
    const pngEof = Buffer.from("\x00\x00\x00\x00IEND\xaeB\x60\x82", "binary");
    const content = Buffer.concat([Buffer.alloc(100, 0x01), pngEof, Buffer.from("MZ_appended_payload_data")]);
    const findings = detectPolyglots(content);
    expect(findings.some((f) => f.includes("Appended"))).toBe(true);
  });
});

describe("detectXlmMacros", () => {
  it("flags 3+ legacy XLM opcodes", () => {
    const content = Buffer.from("some binary blob EXEC REGISTER CALL more data");
    expect(detectXlmMacros(content)).toHaveLength(1);
  });

  it("does not flag fewer than 3 opcodes", () => {
    const content = Buffer.from("just EXEC once in this buffer");
    expect(detectXlmMacros(content)).toHaveLength(0);
  });
});

describe("pdfForensicSignals", () => {
  it("detects JavaScript and launch actions", () => {
    const content = Buffer.from("<< /JavaScript (app.alert()) /Launch (cmd.exe) >>");
    const signals = pdfForensicSignals(content);
    expect(signals.hasJs).toBe(true);
    expect(signals.hasLaunch).toBe(true);
  });

  it("detects evasion (ObjStm without XRef)", () => {
    const content = Buffer.from("<< /Type /ObjStm /N 5 >>");
    expect(pdfForensicSignals(content).evasionDetected).toBe(true);
  });

  it("does not flag a clean PDF fragment", () => {
    const content = Buffer.from("%PDF-1.4\n<< /Type /Catalog /Pages 2 0 R >>\n%%EOF");
    const signals = pdfForensicSignals(content);
    expect(signals.hasJs).toBe(false);
    expect(signals.hasLaunch).toBe(false);
  });
});

describe("inferMitreTechniques", () => {
  it("maps signals to their technique IDs, deduped and sorted", () => {
    const techniques = inferMitreTechniques({ autoExec: true, obfuscation: true, hasMacros: false });
    expect(techniques).toEqual(["T1027", "T1204.002"]);
  });

  it("returns an empty list when no signals are set", () => {
    expect(inferMitreTechniques({})).toHaveLength(0);
  });
});
