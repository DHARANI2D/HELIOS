"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { db } from "@/lib/db";
import { action } from "@/lib/action";
import { logAction } from "@/lib/audit";
import { openSealed } from "@/lib/keys";
import { requirePermission, type SessionUser } from "@/lib/session";
import { evaluateGuard } from "@/lib/aisec/guard";
import { STAGES, type Stage } from "@/lib/aisec/policy";
import { verifyReceipt } from "@/lib/aisec/receipts";
import { DATA_CLASSES, KINDS, applyPackToSystem, applyRecommendations, issueKey, modeOf, policyOf, registerSystem, revokeKey, savePolicy, updateProfile, type AiActor, type SystemKind } from "@/lib/aisec/service";

// AI Security: every call re-checks the permission, and a client user only
// ever reaches their own client's AI systems.

const actorOf = (u: SessionUser): AiActor => ({ id: u.id, name: u.name ?? u.email ?? "user", role: u.role, isClient: u.isClient, tenantId: u.tenantId });

async function systemActor(systemId: string, permission: "aisec.view" | "aisec.manage") {
  const user = await requirePermission(permission);
  const s = await db.aiSystem.findUnique({ where: { id: systemId }, select: { tenantId: true } });
  if (!s || (user.isClient && user.tenantId !== s.tenantId)) throw new Error("Not found");
  return { user, actor: actorOf(user) };
}

const done = (systemId?: string) => {
  revalidatePath("/ai-security");
  if (systemId) revalidatePath(`/ai-security/${systemId}`);
};

const registerSchema = z.object({
  tenantId: z.string().max(64),
  name: z.string().trim().min(1).max(120),
  kind: z.enum(Object.keys(KINDS) as [SystemKind, ...SystemKind[]]),
  description: z.string().max(2000).optional(),
  owner: z.string().max(200).optional(),
  dataClasses: z.array(z.enum(Object.keys(DATA_CLASSES) as [string, ...string[]])).max(10),
  endpoint: z.string().max(500).optional(),
});

export const registerSystemAction = action(async function registerSystemAction(input: z.input<typeof registerSchema>) {
  const user = await requirePermission("aisec.manage");
  const s = registerSchema.parse(input);
  const tenantId = user.isClient ? user.tenantId : s.tenantId;
  if (!tenantId) throw new Error("Pick the client");
  const system = await registerSystem({ ...s, tenantId }, actorOf(user));
  done();
  return { id: system.id };
});

const profileSchema = z.object({
  name: z.string().max(120).optional(),
  description: z.string().max(2000).nullable().optional(),
  owner: z.string().max(200).nullable().optional(),
  dataClasses: z.array(z.string().max(40)).max(10).optional(),
  status: z.enum(["active", "paused", "retired"]).optional(),
  endpoint: z.string().max(500).nullable().optional(),
  endpointFormat: z.enum(["openai", "json"]).optional(),
  endpointModel: z.string().max(120).nullable().optional(),
  requestTemplate: z.string().max(5000).nullable().optional(),
  responsePath: z.string().max(200).nullable().optional(),
  authHeader: z.string().max(60).nullable().optional(),
  authValue: z.string().max(4000).optional(),
  upstreamUrl: z.string().max(500).nullable().optional(),
  upstreamModel: z.string().max(120).nullable().optional(),
  upstreamKey: z.string().max(4000).optional(),
  privacyMode: z.boolean().optional(),
  retainContent: z.boolean().optional(),
});

export const updateProfileAction = action(async function updateProfileAction(systemId: string, input: z.input<typeof profileSchema>) {
  const { actor } = await systemActor(systemId, "aisec.manage");
  await updateProfile(systemId, profileSchema.parse(input), actor);
  done(systemId);
});

export const savePolicyAction = action(async function savePolicyAction(systemId: string, policy: unknown, mode: "enforce" | "monitor", reason: string) {
  const { actor } = await systemActor(systemId, "aisec.manage");
  const r = await savePolicy(systemId, policy, z.enum(["enforce", "monitor"]).parse(mode), z.string().max(1000).parse(reason), actor);
  done(systemId);
  return r;
});

export const applyPackAction = action(async function applyPackAction(systemId: string, pack: string) {
  const { actor } = await systemActor(systemId, "aisec.manage");
  const r = await applyPackToSystem(systemId, z.string().max(40).parse(pack), actor);
  done(systemId);
  return r;
});

export const applyRecommendationsAction = action(async function applyRecommendationsAction(systemId: string, ids: string[]) {
  const { actor } = await systemActor(systemId, "aisec.manage");
  const r = await applyRecommendations(systemId, z.array(z.string().max(40)).max(20).parse(ids), actor);
  done(systemId);
  return r;
});

// The key is returned once, here; only its hash is kept.
export const issueKeyAction = action(async function issueKeyAction(systemId: string) {
  const { actor } = await systemActor(systemId, "aisec.manage");
  const r = await issueKey(systemId, actor);
  done(systemId);
  return r;
});

export const revokeKeyAction = action(async function revokeKeyAction(systemId: string) {
  const { actor } = await systemActor(systemId, "aisec.manage");
  await revokeKey(systemId, actor);
  done(systemId);
});

const benchSchema = z.object({
  stage: z.enum(Object.keys(STAGES) as [Stage, ...Stage[]]),
  content: z.string().max(50_000).optional(),
  tool: z.object({ name: z.string().max(120), args: z.record(z.string(), z.unknown()) }).optional(),
  documents: z.array(z.object({ id: z.string().max(200), text: z.string().max(50_000), access: z.array(z.string().max(80)).max(20).optional() })).max(20).optional(),
  user: z.object({ roles: z.array(z.string().max(80)).max(20).optional() }).optional(),
  task: z.string().max(120).optional(),
  confirmed: z.boolean().optional(),
});

// Tries the policy on a sample without recording anything: the policy
// editor's test bench. With a draft policy, tries that instead.
export const testBenchAction = action(async function testBenchAction(systemId: string, input: z.input<typeof benchSchema>, draft?: unknown) {
  await systemActor(systemId, "aisec.view");
  const s = await db.aiSystem.findUniqueOrThrow({ where: { id: systemId } });
  const policy = draft ? policyOf({ policy: draft as never }) : policyOf(s);
  const req = benchSchema.parse(input);
  // "CANARY" in a sample stands in for this system's canary.
  if (req.content) req.content = req.content.replaceAll("CANARY", s.canary);
  return evaluateGuard({ policy, mode: modeOf(s), canary: s.canary }, req);
});

// A retained prompt or answer, opened for someone allowed to manage the
// system; every opening is in the audit log.
export const revealContentAction = action(async function revealContentAction(systemId: string, eventId: string) {
  const { user } = await systemActor(systemId, "aisec.manage");
  const s = await db.aiSystem.findUniqueOrThrow({ where: { id: systemId }, select: { tenantId: true, name: true } });
  const ev = await db.securityEvent.findFirst({ where: { id: z.string().max(64).parse(eventId), tenantId: s.tenantId, platform: "helios-ai-guard" }, select: { metadata: true, timestamp: true } });
  const sealed = (ev?.metadata as { sealedContent?: string; systemId?: string } | null) ?? null;
  if (!ev || sealed?.systemId !== systemId || !sealed.sealedContent) throw new Error("No content was kept for this decision");
  await logAction({ actorId: user.id, action: "aisec.content_opened", detail: { systemId, name: s.name, eventId, at: ev.timestamp } });
  return JSON.parse(await openSealed(sealed.sealedContent)) as { stage: string; content: string | null; tool: unknown; documents: Array<{ id: string; text: string }> | null };
});

export const verifyReceiptAction = action(async function verifyReceiptAction(text: string) {
  await requirePermission("aisec.view");
  let r: { body?: unknown; keyId?: string; signature?: string };
  try {
    r = JSON.parse(z.string().max(20_000).parse(text));
  } catch {
    throw new Error("Paste the receipt as JSON: { body, keyId, signature }");
  }
  if (!r.body || typeof r.signature !== "string") throw new Error("A receipt has body, keyId and signature");
  return verifyReceipt({ body: r.body, keyId: r.keyId, signature: r.signature });
});
