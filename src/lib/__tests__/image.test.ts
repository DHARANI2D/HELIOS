import { readFileSync } from "node:fs";
import { afterAll, describe, expect, it } from "vitest";

import { inspectImage, isRasterImage, stopOcr } from "@/lib/forensics/image";

const fixture = (name: string) => new Uint8Array(readFileSync(new URL(`./fixtures/images/${name}`, import.meta.url)));

describe("image inspection", () => {
  afterAll(() => stopOcr());

  it("recognizes raster images by their bytes", () => {
    expect(isRasterImage(fixture("qr-lure.png"))).toBe(true);
    expect(isRasterImage(fixture("text-lure.jpg"))).toBe(true);
    expect(isRasterImage(new TextEncoder().encode("<svg xmlns='http://www.w3.org/2000/svg'/>"))).toBe(false);
  });

  it("decodes a QR code", async () => {
    const r = await inspectImage(fixture("qr-lure.png"), { ocr: false });
    expect(r.qr).toEqual(["https://login-microsoft365-secure.example.xyz/owa/?u=jdoe"]);
  });

  it("reads the text of a lure rendered as a picture", async () => {
    const r = await inspectImage(fixture("text-lure.jpg"));
    expect(r.error).toBeUndefined();
    expect(r.text).toMatch(/mailbox password expires today/i);
    expect(r.text).toContain("https://mail-verify.example.top/login");
  }, 60_000);

  it("reports an unreadable file instead of throwing", async () => {
    const r = await inspectImage(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 0, 0, 0, 0, 0]));
    expect(r.error).toMatch(/Unreadable image/);
  });
});

describe("image findings in attachment analysis", () => {
  it("scores a QR link like a phishing link and reads the lure text", async () => {
    const { analyzeFile, applyImageFindings } = await import("@/lib/forensics/files");
    const bytes = fixture("qr-lure.png");
    const before = analyzeFile("scan-me.png", bytes);
    const after = applyImageFindings(before, { width: 300, height: 300, qr: ["https://login-microsoft365-secure.example.xyz/owa/?u=jdoe"], text: "Scan to keep your Microsoft 365 password from expiring. Verify your account now." });
    expect(after.signals.qrLink).toBe(true);
    expect(after.techniques).toContain("T1566.002");
    expect(after.urls).toContain("https://login-microsoft365-secure.example.xyz/owa/?u=jdoe");
    expect(after.reasons).toContain("QR code opens https://login-microsoft365-secure.example.xyz/owa/?u=jdoe");
    expect(after.reasons.some((r) => r.startsWith("Text in image:"))).toBe(true);
    expect(after.score).toBeGreaterThan(before.score + 25);
  });
});
