import { readFileSync } from "node:fs";
import { unzipSync } from "fflate";
import { describe, expect, it } from "vitest";

import { readCfb } from "@/lib/forensics/cfb";
import { decompressVba, extractVba } from "@/lib/forensics/vba";
import { analyzeFile } from "@/lib/forensics/files";
import { DROPPER_MACRO } from "@/lib/__tests__/fixtures/macros";
import { buildMacroDocument, compressLiterals } from "@/lib/__tests__/fixtures/vba-builder";

const fixture = (name: string) => new Uint8Array(readFileSync(new URL(`./fixtures/office/${name}`, import.meta.url)));

describe("VBA macro source", () => {
  it("matches olevba on a project saved by Word", () => {
    const zip = unzipSync(fixture("oleform-PR314.docm"));
    const modules = extractVba(zip["word/vbaProject.bin"]);
    const reference = JSON.parse(readFileSync(new URL("./fixtures/office/oleform-PR314.olevba.json", import.meta.url), "utf8")) as Record<string, string>;
    expect(Object.fromEntries(modules.map((m) => [m.stream, m.code]))).toEqual(reference);
  });

  it("reads a legacy Word document's Macros storage", () => {
    const doc = buildMacroDocument(DROPPER_MACRO);
    expect(readCfb(doc).entries.map((e) => e.path)).toEqual(expect.arrayContaining(["Macros/VBA/dir", "Macros/VBA/ThisDocument", "WordDocument"]));
    const modules = extractVba(doc);
    expect(modules.map((m) => m.name)).toEqual(["ThisDocument", "Helpers"]); // project order
    expect(modules.find((m) => m.name === "ThisDocument")!.code).toBe(DROPPER_MACRO[0].code);
  });

  it("decompresses literal and copy tokens", () => {
    expect(Buffer.from(decompressVba(Uint8Array.from(compressLiterals([...Buffer.from("Sub A()")])))).toString()).toBe("Sub A()");
    // [MS-OVBA] 3.2.3 example: "#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"
    const compressed = Uint8Array.from([0x01, 0x2f, 0xb0, 0x00, 0x23, 0x61, 0x61, 0x61, 0x62, 0x63, 0x64, 0x65, 0x82, 0x66, 0x00, 0x70, 0x61, 0x67, 0x68, 0x69, 0x6a, 0x01, 0x38, 0x08, 0x61, 0x6b, 0x6c, 0x00, 0x30, 0x6d, 0x6e, 0x6f, 0x70, 0x06, 0x71, 0x02, 0x70, 0x04, 0x10, 0x72, 0x73, 0x74, 0x75, 0x76, 0x10, 0x77, 0x78, 0x79, 0x7a, 0x00, 0x3c]);
    expect(Buffer.from(decompressVba(compressed)).toString()).toBe("#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa");
  });

  it("analyzes the macro source itself, not the compressed bytes", () => {
    const a = analyzeFile("invoice.doc", buildMacroDocument(DROPPER_MACRO));
    expect(a.macros?.map((m) => m.name)).toEqual(["ThisDocument", "Helpers"]);
    expect(a.signals).toMatchObject({ hasMacros: true, autoExec: true, envFingerprinting: true });
    expect(a.signals.suspiciousCalls).toEqual(expect.arrayContaining(["WScript.Shell interaction", "Network download (URLDownloadToFile)"]));
    expect(a.reasons.some((r) => r.includes("keyword scan of the compressed"))).toBe(false);
    expect(a.risk).toBe("Malicious");
  });

  it("returns nothing for a file without a VBA project", () => {
    expect(extractVba(new Uint8Array(1024))).toEqual([]);
  });
});
