import { describe, expect, it } from "vitest";

import { archiveLines, heldBetween, packArchive, unpackArchive } from "@/lib/retention/service";
import { inIndia, residency } from "@/lib/retention/storage";

describe("the event archive", () => {
  const day = new Date("2026-04-01T00:00:00Z");
  const rows = [{ id: "e1", eventType: "process_start", hostName: "WS-1" }, { id: "e2", eventType: "network_connect", destIp: "203.0.113.9" }];

  it("round-trips compressed, encrypted, hashed objects", async () => {
    const packed = await packArchive(rows, null, day, 1);
    expect(packed.body.subarray(0, 4).toString()).toBe("HLA1");
    expect(packed.body.includes(Buffer.from("WS-1"))).toBe(false);
    const gz = await unpackArchive(packed.body, { sha256: packed.sha256, keySealed: packed.keySealed, tenantId: null, day, part: 1 });
    expect(archiveLines(gz)).toEqual(rows);
  });

  it("refuses an object that was changed, or opened as another day", async () => {
    const packed = await packArchive(rows, null, day, 1);
    const meta = { sha256: packed.sha256, keySealed: packed.keySealed, tenantId: null, day, part: 1 };
    const tampered = Buffer.from(packed.body);
    tampered[tampered.length - 1] ^= 1;
    await expect(unpackArchive(tampered, meta)).rejects.toThrow(/doesn't match its recorded hash/);
    await expect(unpackArchive(packed.body, { ...meta, day: new Date("2026-04-02T00:00:00Z") })).rejects.toThrow();
  });

  it("knows what a hold covers and where India is", () => {
    const holds = [{ fromAt: new Date("2026-03-01T00:00:00Z"), toAt: new Date("2026-03-31T23:59:59Z") }, { fromAt: new Date("2026-06-01T00:00:00Z"), toAt: null }];
    const dayOf = (s: string) => [new Date(`${s}T00:00:00Z`), new Date(`${s}T23:59:59Z`)] as const;
    expect(heldBetween(holds, ...dayOf("2026-03-15"))).toBe(true);
    expect(heldBetween(holds, ...dayOf("2026-04-15"))).toBe(false);
    expect(heldBetween(holds, ...dayOf("2027-01-01"))).toBe(true);
    expect(["ap-south-1", "ap-south-2", "India", "in", "centralindia", "asia-south1"].map(inIndia)).toEqual([true, true, true, true, true, true]);
    expect(["us-east-1", "eu-west-1", "asia-southeast1", "southeastasia", null].map(inIndia)).toEqual([false, false, false, false, false]);
  });

  it("shows the logs in India only when the database and the archive both are", () => {
    const env = { ...process.env };
    try {
      process.env.HELIOS_DATA_REGION = "ap-south-1";
      delete process.env.HELIOS_ARCHIVE_S3_BUCKET;
      delete process.env.HELIOS_ARCHIVE_DIR;
      expect(residency().inIndia).toBe(true);
      process.env.HELIOS_ARCHIVE_S3_BUCKET = "logs";
      process.env.HELIOS_ARCHIVE_S3_REGION = "eu-west-1";
      expect(residency()).toMatchObject({ inIndia: false, store: { kind: "s3", inIndia: false }, database: { inIndia: true } });
      process.env.HELIOS_ARCHIVE_S3_REGION = "ap-south-1";
      delete process.env.HELIOS_DATA_REGION;
      expect(residency()).toMatchObject({ inIndia: false, store: { inIndia: true }, database: { region: null } });
    } finally {
      process.env = env;
    }
  });
});
