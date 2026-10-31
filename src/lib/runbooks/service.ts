import { Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { RUNBOOK_TEMPLATES } from "@/lib/runbooks/templates";
import { matchSchema, matchScore, parseProgress, parseSteps, progressOf, runbookSchema, type RunbookInput, type StepState } from "@/lib/runbooks/match";

// Runbooks: written procedures attached to the cases they match, worked as
// a checklist. A case keeps the steps as they were when it got them, so
// editing a runbook doesn't rewrite cases already worked. A true positive
// can't be closed with a required step neither done nor skipped (with a
// reason).

const MAX_PER_CASE = 3;

export async function saveRunbook(id: string | null, input: RunbookInput & { tenantId: string | null }, actorId: string) {
  const { title, description, match, steps } = runbookSchema.parse(input);
  if (input.tenantId && !(await db.tenant.count({ where: { id: input.tenantId } }))) throw new Error("Not found");
  const data = { title, description: description || null, match, steps, tenantId: input.tenantId, updatedById: actorId };
  if (!id) {
    const created = await db.runbook.create({ data: { ...data, createdById: actorId } });
    await logAction({ actorId, action: "runbook.created", detail: { runbookId: created.id, title, tenantId: input.tenantId } });
    return created;
  }
  const before = await db.runbook.findUniqueOrThrow({ where: { id } });
  const changed = JSON.stringify(before.steps) !== JSON.stringify(steps) || JSON.stringify(before.match) !== JSON.stringify(match);
  const saved = await db.runbook.update({ where: { id }, data: { ...data, ...(changed ? { version: { increment: 1 } } : {}) } });
  await logAction({ actorId, action: "runbook.updated", detail: { runbookId: id, title, version: saved.version } });
  return saved;
}

export async function setRunbookEnabled(id: string, enabled: boolean, actorId: string) {
  await db.runbook.update({ where: { id }, data: { enabled, updatedById: actorId } });
  await logAction({ actorId, action: enabled ? "runbook.enabled" : "runbook.disabled", detail: { runbookId: id } });
}

export async function deleteRunbook(id: string, actorId: string) {
  const r = await db.runbook.delete({ where: { id } });
  await logAction({ actorId, action: "runbook.deleted", detail: { runbookId: id, title: r.title } });
}

// The starter runbooks not already there (by title).
export async function installTemplates(actorId: string) {
  const have = new Set((await db.runbook.findMany({ where: { tenantId: null }, select: { title: true } })).map((r) => r.title.toLowerCase()));
  const missing = RUNBOOK_TEMPLATES.filter((t) => !have.has(t.title.toLowerCase()));
  for (const t of missing) await saveRunbook(null, { ...t, tenantId: null }, actorId);
  return missing.length;
}

// ---------------------------------------------------------------- on cases

async function caseFacts(caseId: string) {
  const kase = await db.case.findUniqueOrThrow({ where: { id: caseId }, select: { id: true, tenantId: true, sourceType: true, severity: true, title: true, mitreTechniques: { select: { techniqueId: true } } } });
  return { kase, facts: { source: kase.sourceType, severity: kase.severity, title: kase.title, techniques: kase.mitreTechniques.map((t) => t.techniqueId) } };
}

async function attach(caseId: string, tenantId: string | null, runbook: { id: string; title: string; version: number; steps: Prisma.JsonValue }, by: string) {
  try {
    await db.caseRunbook.create({ data: { caseId, tenantId, runbookId: runbook.id, title: runbook.title, version: runbook.version, steps: runbook.steps ?? [], attachedBy: by } });
  } catch (e) {
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") return false;
    throw e;
  }
  await db.timelineEntry.create({ data: { caseId, occurredAt: new Date(), actor: by === "matched" ? "runbooks" : by, action: "runbook.attached", detail: `Runbook "${runbook.title}" (v${runbook.version})${by === "matched" ? " matched this case" : " attached"}` } });
  return true;
}

// Called when a case is created or updated: the best-matching runbooks,
// the client's own first.
export async function attachRunbooks(caseId: string) {
  const { kase, facts } = await caseFacts(caseId);
  const [runbooks, attached] = await Promise.all([
    db.runbook.findMany({ where: { enabled: true, OR: [{ tenantId: null }, ...(kase.tenantId ? [{ tenantId: kase.tenantId }] : [])] } }),
    db.caseRunbook.count({ where: { caseId } }),
  ]);
  const room = MAX_PER_CASE - attached;
  if (room <= 0 || !runbooks.length) return 0;
  const scored = runbooks
    .map((r) => {
      const m = matchSchema.safeParse(r.match);
      return { r, score: m.success ? matchScore(m.data, facts) : null };
    })
    .filter((x): x is { r: (typeof runbooks)[number]; score: number } => x.score != null)
    .sort((a, b) => Number(!!b.r.tenantId) - Number(!!a.r.tenantId) || b.score - a.score);
  let n = 0;
  for (const { r } of scored) {
    if (n >= room) break;
    if (await attach(caseId, kase.tenantId, r, "matched")) n++;
  }
  return n;
}

export async function attachRunbook(caseId: string, runbookId: string, actor: { id: string; name: string }) {
  const { kase } = await caseFacts(caseId);
  const r = await db.runbook.findUniqueOrThrow({ where: { id: runbookId } });
  if (r.tenantId && r.tenantId !== kase.tenantId) throw new Error("That runbook is another client's");
  if (!(await attach(caseId, kase.tenantId, r, actor.name))) throw new Error("It's already on this case");
  await logAction({ actorId: actor.id, caseId, action: "runbook.attached", detail: { runbookId, version: r.version } });
}

// Ticks a step, skips it (with a reason), or clears it. The progress is
// merged in the database, so two people working different steps at once
// don't overwrite each other.
export async function setStep(caseRunbookId: string, stepId: string, change: { state: "done" | "skipped" | "open"; note?: string }, actor: { id: string; name: string }) {
  const cr = await db.caseRunbook.findUniqueOrThrow({ where: { id: caseRunbookId } });
  const step = parseSteps(cr.steps).find((s) => s.id === stepId);
  if (!step) throw new Error("Not found");
  const note = change.note?.trim().slice(0, 1000) || undefined;
  if (change.state === "skipped" && (!note || note.length < 3)) throw new Error("Say why the step is skipped");
  if (change.state === "open") {
    await db.$executeRaw`UPDATE case_runbooks SET progress = progress - ${stepId} WHERE id = ${caseRunbookId}`;
  } else {
    const state: StepState = { by: actor.name, byId: actor.id, at: new Date().toISOString(), ...(note ? { note } : {}), ...(change.state === "skipped" ? { skipped: true } : {}) };
    await db.$executeRaw`UPDATE case_runbooks SET progress = progress || jsonb_build_object(${stepId}::text, ${JSON.stringify(state)}::jsonb) WHERE id = ${caseRunbookId}`;
  }
  const after = await db.caseRunbook.findUniqueOrThrow({ where: { id: caseRunbookId } });
  const p = progressOf(parseSteps(after.steps), parseProgress(after.progress));
  if (p.complete !== !!after.completedAt) await db.caseRunbook.update({ where: { id: caseRunbookId }, data: { completedAt: p.complete ? new Date() : null } });
  const verb = change.state === "done" ? "done" : change.state === "skipped" ? `skipped: ${note}` : "reopened";
  await db.timelineEntry.create({ data: { caseId: cr.caseId, occurredAt: new Date(), actor: actor.name, action: "runbook.step", detail: `${cr.title}: "${step.title}" ${verb}${p.complete && !after.completedAt ? " (runbook complete)" : ""}` } });
  await logAction({ actorId: actor.id, caseId: cr.caseId, action: "runbook.step", detail: { caseRunbookId, stepId, state: change.state, note } });
}

export async function removeFromCase(caseRunbookId: string, actor: { id: string; name: string }) {
  const cr = await db.caseRunbook.delete({ where: { id: caseRunbookId } });
  await db.timelineEntry.create({ data: { caseId: cr.caseId, occurredAt: new Date(), actor: actor.name, action: "runbook.removed", detail: `Runbook "${cr.title}" taken off the case` } });
  await logAction({ actorId: actor.id, caseId: cr.caseId, action: "runbook.removed", detail: { caseRunbookId, title: cr.title } });
}

// Required steps neither done nor skipped, by runbook.
export async function openRequiredSteps(caseId: string) {
  const rows = await db.caseRunbook.findMany({ where: { caseId } });
  return rows
    .map((r) => ({ title: r.title, steps: progressOf(parseSteps(r.steps), parseProgress(r.progress)).requiredOpen.map((s) => s.title) }))
    .filter((r) => r.steps.length > 0);
}
