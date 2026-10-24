import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { extractZip, passwordsInText, readZipDirectory } from "@/lib/archive/zip";

const fixture = (name: string) => new Uint8Array(readFileSync(new URL(`./fixtures/archives/${name}`, import.meta.url)));
const VBS = fixture("invoice.vbs");
const LOG = fixture("notes.log");

describe("ZIP reader", () => {
  it("lists members and their encryption", () => {
    expect(readZipDirectory(fixture("zipcrypto.zip")).map((m) => [m.name, m.encrypted, m.aesStrength])).toEqual([
      ["invoice.vbs", true, undefined],
      ["notes.log", true, undefined],
      ["filler.txt", true, undefined],
    ]);
    expect(readZipDirectory(fixture("aes256.zip"))[0]).toMatchObject({ encrypted: true, aesStrength: 3, method: 8 });
  });

  it("opens traditional PKWARE encryption (Info-ZIP zip -P)", () => {
    const r = extractZip(fixture("zipcrypto.zip"), { passwords: ["wrong", "Inv-2026!"] });
    expect(r.locked).toEqual([]);
    expect(r.passwordUsed).toBe("Inv-2026!");
    expect(r.files["invoice.vbs"]).toEqual(VBS);
    expect(r.files["notes.log"]).toEqual(LOG);
    expect(Object.keys(r.files)).toHaveLength(3);
  });

  it("checks the time byte when the archive was streamed with a data descriptor", () => {
    const r = extractZip(fixture("streamed.zip"), { passwords: ["stream-pw"] });
    expect(Object.values(r.files)).toEqual([VBS]);
  });

  it.each(["aes128.zip", "aes256.zip"])("opens WinZip AES (%s, pyzipper)", (name) => {
    const r = extractZip(fixture(name), { passwords: ["infected"] });
    expect(r.locked).toEqual([]);
    expect(r.files["invoice.vbs"]).toEqual(VBS);
    expect(r.files["notes.log"]).toEqual(LOG);
  });

  it("reports locked members instead of returning garbage", () => {
    expect(extractZip(fixture("aes128.zip")).locked.map((l) => l.reason)).toEqual(["no-password", "no-password", "no-password"]);
    const wrong = extractZip(fixture("zipcrypto.zip"), { passwords: ["nope", "letmein"] });
    expect(wrong.files).toEqual({});
    expect(wrong.locked.every((l) => l.reason === "wrong-password")).toBe(true);
  });

  it("reads unencrypted archives too", () => {
    expect(extractZip(fixture("plain.zip")).files["notes.log"]).toEqual(LOG);
  });
});

describe("passwords quoted in a message", () => {
  it("finds the usual phrasings", () => {
    const body = "Invoice attached. The password is 4471.\nPW: Inv-2026!\nArchive passwort: geheim99\nPlease reset your password below.";
    expect(passwordsInText(body)).toEqual(["4471", "Inv-2026!", "geheim99"]);
  });
});

describe("encrypted archives in forensics and investigations", () => {
  it("opens an attachment with a password quoted in the message and analyzes what's inside", async () => {
    const { analyzeFile } = await import("@/lib/forensics/files");
    const locked = analyzeFile("invoice.zip", fixture("zipcrypto.zip"));
    expect(locked.signals.encryptedArchive).toBe(true);
    expect(locked.techniques).toContain("T1027.013");
    expect(locked.children ?? []).toEqual([]);

    const opened = analyzeFile("invoice.zip", fixture("zipcrypto.zip"), undefined, 0, { quotedPasswords: passwordsInText("Your invoice is attached. Password: Inv-2026!") });
    expect(opened.archiveUnlocked).toBe(true);
    expect(opened.reasons).toContain("Opened with a password quoted in the message — the usual way to slip a payload past gateway scanning");
    const vbs = opened.children?.find((c) => c.filename === "invoice.vbs");
    expect(vbs?.signals.suspiciousCalls.length).toBeGreaterThan(0);
    expect(opened.score).toBeGreaterThan(locked.score);
  });

  it("expands a password-protected log bundle, and says when the password is missing", async () => {
    const { expandIntake } = await import("@/lib/investigations/service");
    const withPassword = expandIntake([{ name: "bundle.zip", bytes: fixture("aes256.zip") }], { passwords: ["infected"] });
    expect(withPassword.texts.map((t) => t.name)).toEqual(expect.arrayContaining(["bundle.zip/notes.log", "bundle.zip/invoice.vbs"]));
    const without = expandIntake([{ name: "bundle.zip", bytes: fixture("aes256.zip") }]);
    expect(without.texts).toEqual([]);
    expect(without.skipped).toContain("bundle.zip/notes.log (password-protected — enter the archive password)");
  });
});
