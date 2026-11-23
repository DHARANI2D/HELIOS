import { createHash, createPrivateKey, createPublicKey, randomUUID, sign, verify, type KeyObject } from "node:crypto";

import { derivedKey } from "@/lib/secrets";
import type { Stage, Verdict } from "@/lib/aisec/policy";

// A signed receipt for every guard decision: which system, which stage,
// what was decided under which policy version, a hash of the content (never
// the content), and when. Signed with an Ed25519 key derived from the
// platform's master key, so anyone holding the public key (GET
// /api/v1/ai/receipts) can check a receipt offline, and nobody without the
// master key can forge one. Changing the master key changes the signing
// key; receipts carry the key id they were signed with.

export interface ReceiptBody {
  v: 1;
  id: string;
  system: string;
  stage: Stage;
  decision: Verdict;
  enforced: Verdict;
  rules: string[];
  contentSha256: string | null;
  policyVersion: number;
  at: string;
}

export interface Receipt {
  body: ReceiptBody;
  keyId: string;
  signature: string;
}

const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");

let cached: { privateKey: KeyObject; publicKey: KeyObject; keyId: string } | null = null;

function keys() {
  if (cached) return cached;
  const seed = derivedKey("ai-guard-receipts-ed25519");
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey);
  const raw = publicKey.export({ type: "spki", format: "der" });
  cached = { privateKey, publicKey, keyId: createHash("sha256").update(raw).digest("hex").slice(0, 16) };
  return cached;
}

// Sorted keys at every level: the same receipt always signs the same bytes.
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(value);
}

export const contentHash = (text: string | undefined | null) => (text ? createHash("sha256").update(text).digest("hex") : null);

export function issueReceipt(input: Omit<ReceiptBody, "v" | "id" | "at">, at = new Date()): Receipt {
  const body: ReceiptBody = { v: 1, id: `rcpt_${randomUUID().replace(/-/g, "").slice(0, 20)}`, ...input, rules: [...new Set(input.rules)].slice(0, 30), at: at.toISOString() };
  const k = keys();
  return { body, keyId: k.keyId, signature: sign(null, Buffer.from(canonical(body)), k.privateKey).toString("base64") };
}

export function verifyReceipt(r: { body: unknown; keyId?: string; signature: string }): { valid: boolean; reason: string } {
  const k = keys();
  if (r.keyId && r.keyId !== k.keyId) return { valid: false, reason: `Signed with key ${r.keyId}, not this platform's current key ${k.keyId}` };
  try {
    const ok = verify(null, Buffer.from(canonical(r.body)), k.publicKey, Buffer.from(r.signature, "base64"));
    return ok ? { valid: true, reason: "The signature matches: HELIOS issued this receipt and it hasn't been changed" } : { valid: false, reason: "The signature doesn't match: the receipt was changed, or not issued by this platform" };
  } catch {
    return { valid: false, reason: "Not a readable receipt" };
  }
}

export function receiptKey() {
  const k = keys();
  return { keyId: k.keyId, algorithm: "Ed25519", publicKeyPem: k.publicKey.export({ type: "spki", format: "pem" }).toString() };
}
