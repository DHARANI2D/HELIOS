import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { derivedKey, masterKeySource, seal, setKmsRootKey, unseal } from "@/lib/secrets";
import { signAws } from "@/lib/collectors/auth";

// Envelope encryption for clients' credentials. Each client has its own
// 256-bit data key; it seals that client's integration secrets and its own
// AI provider keys, and is stored only wrapped by a key derived from the
// master key (lib/secrets). The master key can itself be protected by AWS
// KMS: HELIOS_ENCRYPTION_KEY_KMS holds it encrypted, and initKeyManagement
// asks KMS to decrypt it once at startup.
//   v1.<iv>.<tag>.<ct>            platform secrets, sealed with the master key
//   v2.<keyId>.<iv>.<tag>.<ct>    a client's secret, sealed with its data key
// The client and key id are bound in as associated data, so a sealed value
// can't be moved to another client. Rotating re-seals a client's secrets
// under a new data key; destroying a client's keys (offboarding) leaves its
// stored credentials unreadable, even from a backup.

const WRAP_PURPOSE = "tenant-data-key-wrapping";
const cache = new Map<string, { tenantId: string; key: Buffer }>();

function aesSeal(key: Buffer, plaintext: Buffer, aad: string) {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(Buffer.from(aad));
  const body = Buffer.concat([c.update(plaintext), c.final()]);
  return [iv.toString("base64"), c.getAuthTag().toString("base64"), body.toString("base64")].join(".");
}

function aesOpen(key: Buffer, sealed: string, aad: string) {
  const [iv, tag, body] = sealed.split(".");
  if (!iv || !tag || !body) throw new Error("Unrecognized sealed value");
  const d = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64"));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(Buffer.from(tag, "base64"));
  return Buffer.concat([d.update(Buffer.from(body, "base64")), d.final()]);
}

const wrapAad = (tenantId: string, version: number) => `helios-dek:${tenantId}:${version}`;

async function createKey(tenantId: string) {
  const last = await db.tenantKey.findFirst({ where: { tenantId }, orderBy: { version: "desc" }, select: { version: true } });
  const version = (last?.version ?? 0) + 1;
  const key = randomBytes(32);
  const row = await db.tenantKey.create({ data: { tenantId, version, wrapped: aesSeal(derivedKey(WRAP_PURPOSE), key, wrapAad(tenantId, version)) } });
  cache.set(row.id, { tenantId, key });
  return { id: row.id, key };
}

async function keyById(id: string) {
  const hit = cache.get(id);
  if (hit) return hit;
  const row = await db.tenantKey.findUnique({ where: { id } });
  if (!row) throw new Error("This credential's key no longer exists");
  if (row.destroyedAt) throw new Error("This client's keys were destroyed: its stored credentials can't be read");
  const entry = { tenantId: row.tenantId, key: aesOpen(derivedKey(WRAP_PURPOSE), row.wrapped, wrapAad(row.tenantId, row.version)) };
  cache.set(id, entry);
  return entry;
}

async function currentKey(tenantId: string) {
  const row = await db.tenantKey.findFirst({ where: { tenantId, retiredAt: null, destroyedAt: null }, orderBy: { version: "desc" } });
  if (!row) return createKey(tenantId);
  return { id: row.id, key: (await keyById(row.id)).key };
}

const valueAad = (tenantId: string, keyId: string) => `helios-secret:${tenantId}:${keyId}`;

// Seals a credential: with the client's data key, or the master key for the SOC's own.
export async function sealFor(tenantId: string | null | undefined, plaintext: string): Promise<string> {
  if (!tenantId) return seal(plaintext);
  const { id, key } = await currentKey(tenantId);
  return `v2.${id}.${aesSeal(key, Buffer.from(plaintext, "utf8"), valueAad(tenantId, id))}`;
}

export async function openSealed(sealed: string): Promise<string> {
  if (!sealed.startsWith("v2.")) return unseal(sealed);
  const [, keyId, ...rest] = sealed.split(".");
  const { tenantId, key } = await keyById(keyId);
  return aesOpen(key, rest.join("."), valueAad(tenantId, keyId)).toString("utf8");
}

const keyIdOf = (sealed: string | null) => (sealed?.startsWith("v2.") ? sealed.split(".")[1] : null);

// Every sealed credential that belongs to a client.
async function clientSecrets(tenantId?: string) {
  const [integrations, providers] = await Promise.all([
    db.integration.findMany({ where: { tenantId: tenantId ?? { not: null }, secretCipher: { not: null } }, select: { id: true, tenantId: true, secretCipher: true } }),
    db.aiProvider.findMany({ where: { tenantId: tenantId ?? { not: null }, apiKeyCipher: { not: null } }, select: { id: true, tenantId: true, apiKeyCipher: true } }),
  ]);
  return [
    ...integrations.map((i) => ({ kind: "integration" as const, id: i.id, tenantId: i.tenantId!, sealed: i.secretCipher! })),
    ...providers.map((p) => ({ kind: "provider" as const, id: p.id, tenantId: p.tenantId!, sealed: p.apiKeyCipher! })),
  ];
}

async function reseal(item: Awaited<ReturnType<typeof clientSecrets>>[number], sealed: string) {
  if (item.kind === "integration") await db.integration.update({ where: { id: item.id }, data: { secretCipher: sealed } });
  else await db.aiProvider.update({ where: { id: item.id }, data: { apiKeyCipher: sealed } });
}

// Moves clients' credentials still sealed with the master key onto their own keys.
export async function adoptClientKeys(actorId: string) {
  let moved = 0;
  for (const item of await clientSecrets()) {
    if (item.sealed.startsWith("v2.")) continue;
    await reseal(item, await sealFor(item.tenantId, unseal(item.sealed)));
    moved++;
  }
  await logAction({ actorId, action: "keys.client_keys_adopted", detail: { moved } });
  return moved;
}

// A new data key for the client; its credentials are re-sealed and the old keys retired.
export async function rotateTenantKey(tenantId: string, actorId: string) {
  const old = await db.tenantKey.findMany({ where: { tenantId, retiredAt: null, destroyedAt: null }, select: { id: true } });
  const fresh = await createKey(tenantId);
  let resealed = 0;
  for (const item of await clientSecrets(tenantId)) {
    if (keyIdOf(item.sealed) === fresh.id) continue;
    const plain = await openSealed(item.sealed);
    await reseal(item, `v2.${fresh.id}.${aesSeal(fresh.key, Buffer.from(plain, "utf8"), valueAad(tenantId, fresh.id))}`);
    resealed++;
  }
  await db.tenantKey.updateMany({ where: { id: { in: old.map((k) => k.id) } }, data: { retiredAt: new Date() } });
  await logAction({ actorId, action: "keys.tenant_key_rotated", detail: { tenantId, resealed } });
  return { resealed };
}

// Offboarding: the client's data keys are erased, so whatever is left of
// its credentials (in this database or a backup of it) can't be decrypted.
export async function destroyTenantKeys(tenantId: string, actorId: string) {
  const tenant = await db.tenant.findUniqueOrThrow({ where: { id: tenantId }, select: { status: true, name: true } });
  if (tenant.status !== "SUSPENDED") throw new Error("Suspend the client before destroying its keys");
  const keys = await db.tenantKey.findMany({ where: { tenantId }, select: { id: true } });
  await db.tenantKey.updateMany({ where: { tenantId }, data: { wrapped: "", destroyedAt: new Date() } });
  for (const k of keys) cache.delete(k.id);
  await db.integration.updateMany({ where: { tenantId }, data: { secretCipher: null } });
  await db.aiProvider.updateMany({ where: { tenantId }, data: { apiKeyCipher: null } });
  await logAction({ actorId, action: "keys.tenant_keys_destroyed", detail: { tenantId, name: tenant.name, keys: keys.length } });
  return { destroyed: keys.length };
}

export async function keyReport() {
  const [items, keys] = await Promise.all([clientSecrets(), db.tenantKey.groupBy({ by: ["tenantId"], where: { destroyedAt: null, retiredAt: null }, _count: { _all: true } })]);
  return {
    master: masterKeySource(),
    clientsWithKeys: keys.length,
    onClientKeys: items.filter((i) => i.sealed.startsWith("v2.")).length,
    onMasterKey: items.filter((i) => !i.sealed.startsWith("v2.")).length,
  };
}

// ---------------------------------------------------------------- AWS KMS

// Decrypts the master key with AWS KMS (TrentService.Decrypt, JSON 1.1,
// SigV4) when HELIOS_ENCRYPTION_KEY_KMS is set; a no-op otherwise. Uses
// AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN and
// HELIOS_KMS_REGION (or AWS_REGION).
export async function initKeyManagement(fetchImpl: typeof fetch = fetch) {
  const blob = process.env.HELIOS_ENCRYPTION_KEY_KMS;
  if (!blob) return false;
  const region = process.env.HELIOS_KMS_REGION ?? process.env.AWS_REGION;
  const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
  if (!region || !accessKeyId || !secretAccessKey) throw new Error("HELIOS_ENCRYPTION_KEY_KMS needs HELIOS_KMS_REGION and AWS credentials");
  const url = `https://kms.${region}.amazonaws.com/`;
  const body = JSON.stringify({ CiphertextBlob: blob });
  const headers = signAws(
    { method: "POST", url, region, service: "kms", body, headers: { "content-type": "application/x-amz-json-1.1", "x-amz-target": "TrentService.Decrypt" }, now: new Date() },
    { accessKeyId, secretAccessKey, sessionToken: process.env.AWS_SESSION_TOKEN },
  );
  const res = await fetchImpl(url, { method: "POST", headers, body, signal: AbortSignal.timeout(15_000) });
  const data = (await res.json().catch(() => ({}))) as { Plaintext?: string; message?: string; __type?: string };
  if (!res.ok || !data.Plaintext) throw new Error(`AWS KMS refused to decrypt the master key: ${data.__type ?? res.status} ${data.message ?? ""}`.trim());
  setKmsRootKey(Buffer.from(data.Plaintext, "base64"));
  return true;
}
