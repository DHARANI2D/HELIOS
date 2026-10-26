import { afterEach, describe, expect, it } from "vitest";

import { base32Decode, base32Encode, consumeRecoveryCode, hotp, newRecoveryCodes, otpauthUri, stepAt, totp, verifyTotp } from "@/lib/mfa";
import { initKeyManagement } from "@/lib/keys";
import { seal, unseal } from "@/lib/secrets";

// RFC 6238 appendix B: the SHA-1 seed is the ASCII string "12345678901234567890".
const RFC_SECRET = base32Encode(Buffer.from("12345678901234567890"));

describe("two-step sign-in codes", () => {
  it("matches the RFC 6238 and RFC 4648 test vectors", () => {
    const vectors: Array<[number, string]> = [
      [59, "94287082"],
      [1111111109, "07081804"],
      [1111111111, "14050471"],
      [1234567890, "89005924"],
      [2000000000, "69279037"],
      [20000000000, "65353130"],
    ];
    for (const [seconds, code] of vectors) expect(totp(RFC_SECRET, new Date(seconds * 1000), 8)).toBe(code);
    // RFC 4226 appendix D (HOTP, counter 0 and 9).
    expect(hotp(Buffer.from("12345678901234567890"), 0)).toBe("755224");
    expect(hotp(Buffer.from("12345678901234567890"), 9)).toBe("520489");
    expect(base32Encode(Buffer.from("foobar"))).toBe("MZXW6YTBOI");
    expect(base32Decode("MZXW6YTBOI").toString()).toBe("foobar");
  });

  it("accepts the current code and one step of drift, never the same step twice", () => {
    const now = new Date("2026-10-26T06:00:10Z");
    const code = totp(RFC_SECRET, now);
    const step = verifyTotp(RFC_SECRET, code, { now });
    expect(step).toBe(stepAt(now));
    expect(verifyTotp(RFC_SECRET, code, { now, lastStep: step })).toBeNull();
    expect(verifyTotp(RFC_SECRET, totp(RFC_SECRET, new Date(now.getTime() - 30_000)), { now })).toBe(stepAt(now) - 1);
    expect(verifyTotp(RFC_SECRET, totp(RFC_SECRET, new Date(now.getTime() - 90_000)), { now })).toBeNull();
    expect(verifyTotp(RFC_SECRET, "12345", { now })).toBeNull();
    expect(otpauthUri(RFC_SECRET, "a@x.test", "Acme SOC")).toBe(`otpauth://totp/Acme%20SOC%3Aa%40x.test?secret=${RFC_SECRET}&issuer=Acme+SOC&algorithm=SHA1&digits=6&period=30`);
  });

  it("lets each recovery code in once", () => {
    const { codes, hashes } = newRecoveryCodes();
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);
    expect(hashes.join("")).not.toContain(codes[0].replace("-", ""));
    const left = consumeRecoveryCode(hashes, codes[3].toUpperCase())!;
    expect(left).toHaveLength(9);
    expect(consumeRecoveryCode(left, codes[3])).toBeNull();
  });
});

describe("the KMS-protected master key", () => {
  const env = { ...process.env };
  afterEach(() => {
    process.env = { ...env };
  });

  it("is decrypted once at startup by AWS KMS, then seals as usual", async () => {
    const root = Buffer.alloc(32, 7);
    process.env.HELIOS_ENCRYPTION_KEY_KMS = Buffer.from("ciphertext-blob").toString("base64");
    process.env.HELIOS_KMS_REGION = "ap-south-1";
    process.env.AWS_ACCESS_KEY_ID = "AKIDEXAMPLE";
    process.env.AWS_SECRET_ACCESS_KEY = "secret";
    expect(() => seal("x")).toThrow(/isn't loaded/);
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fake = (async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return new Response(JSON.stringify({ KeyId: "arn:aws:kms:ap-south-1:1:key/k", Plaintext: root.toString("base64") }), { status: 200 });
    }) as unknown as typeof fetch;
    expect(await initKeyManagement(fake)).toBe(true);
    expect(calls[0].url).toBe("https://kms.ap-south-1.amazonaws.com/");
    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers["x-amz-target"]).toBe("TrentService.Decrypt");
    expect(headers.authorization).toMatch(/Credential=AKIDEXAMPLE\/\d{8}\/ap-south-1\/kms\/aws4_request/);
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ CiphertextBlob: process.env.HELIOS_ENCRYPTION_KEY_KMS });
    expect(unseal(seal("credential"))).toBe("credential");

    const refused = (async () => new Response(JSON.stringify({ __type: "AccessDeniedException", message: "not allowed" }), { status: 400 })) as unknown as typeof fetch;
    await expect(initKeyManagement(refused)).rejects.toThrow(/AccessDeniedException not allowed/);
  });
});
