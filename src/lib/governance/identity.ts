import {
  generateKeyPairSync,
  createPublicKey,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";

// Ported from aegis's identity/idp.py (Python `cryptography` Ed25519 keys) to
// Node's built-in crypto, which has native Ed25519 support — no extra
// dependency needed.

export interface AgentIdentity {
  privateKey: KeyObject;
  publicKeyB64: string;
}

export function generateAgentIdentity(): AgentIdentity {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyB64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  return { privateKey, publicKeyB64 };
}

export function signMessage(privateKey: KeyObject, message: string): string {
  const signature = sign(null, Buffer.from(message), privateKey);
  return signature.toString("base64");
}

export function verifySignature(
  publicKeyB64: string,
  message: string,
  signatureB64: string,
): boolean {
  try {
    const publicKey = createPublicKey({
      key: Buffer.from(publicKeyB64, "base64"),
      format: "der",
      type: "spki",
    });
    return verify(
      null,
      Buffer.from(message),
      publicKey,
      Buffer.from(signatureB64, "base64"),
    );
  } catch {
    return false;
  }
}
