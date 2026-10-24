import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

// AES-256-GCM sealing for credentials stored in the database (AI provider
// API keys, tool integration secrets). The key comes from
// HELIOS_ENCRYPTION_KEY (32 bytes, base64) or, failing that, is derived from
// AUTH_SECRET with HKDF — so a database dump alone never yields a usable
// credential. Rotating the key requires re-entering stored secrets.

const VERSION = "v1";

function key(): Buffer {
  const explicit = process.env.HELIOS_ENCRYPTION_KEY;
  if (explicit) {
    const buf = Buffer.from(explicit, "base64");
    if (buf.length !== 32) throw new Error("HELIOS_ENCRYPTION_KEY must be 32 bytes, base64-encoded");
    return buf;
  }
  const secret = process.env.AUTH_SECRET;
  if (!secret || secret === "generate-me") throw new Error("Set HELIOS_ENCRYPTION_KEY or AUTH_SECRET before storing credentials");
  return Buffer.from(hkdfSync("sha256", secret, "helios-secrets", "credential-sealing", 32));
}

export function seal(plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  const body = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return [VERSION, iv.toString("base64"), cipher.getAuthTag().toString("base64"), body.toString("base64")].join(".");
}

export function unseal(sealed: string): string {
  const [version, iv, tag, body] = sealed.split(".");
  if (version !== VERSION || !iv || !tag || !body) throw new Error("Unrecognized sealed secret");
  const decipher = createDecipheriv("aes-256-gcm", key(), Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(body, "base64")), decipher.final()]).toString("utf8");
}

// Ingest tokens: random, shown once, stored as a SHA-256 hash.
export function newToken(prefix: string): { token: string; hash: string; display: string } {
  const token = `${prefix}_${randomBytes(24).toString("base64url")}`;
  return { token, hash: hashToken(token), display: `${token.slice(0, prefix.length + 7)}…` };
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

// "sk-ant-…a1b2": enough to recognize a key without revealing it.
export function maskSecret(secret: string): string {
  if (secret.length <= 8) return "••••";
  return `${secret.slice(0, 6)}…${secret.slice(-4)}`;
}
