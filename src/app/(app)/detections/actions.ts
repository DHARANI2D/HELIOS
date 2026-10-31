"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { db } from "@/lib/db";
import { requirePermission } from "@/lib/session";
import { addTuning, checkRules, deleteRule, importRules, removeTuning, setRuleStatus } from "@/lib/detections/service";
import { TUNING_FIELDS, TUNING_KINDS, TUNING_OPS, type TuningField, type TuningKind, type TuningOp } from "@/lib/detections/tuning";
import { action } from "@/lib/action";

// Detection engineering: Sigma rules and per-client tuning.

const done = () => {
  revalidatePath("/detections");
  revalidatePath("/mitre");
};

async function scope(tenantId: string | null) {
  if (tenantId && !(await db.tenant.count({ where: { id: tenantId } }))) throw new Error("Not found");
  return tenantId;
}

const yaml = z.string().max(500_000, "That's too much to import at once");

export const checkRulesAction = action(async function checkRulesAction(text: string, tenantId: string | null) {
  await requirePermission("detections.tune");
  return checkRules(yaml.parse(text), await scope(tenantId));
});

export const importRulesAction = action(async function importRulesAction(text: string, tenantId: string | null) {
  const user = await requirePermission("detections.tune");
  const results = await importRules(yaml.parse(text), { tenantId: await scope(tenantId), actorId: user.id });
  done();
  return results;
});

export const setRuleStatusAction = action(async function setRuleStatusAction(id: string, status: string) {
  const user = await requirePermission("detections.tune");
  await setRuleStatus(id, z.enum(["TESTING", "ACTIVE", "DISABLED"]).parse(status), user.id);
  done();
});

export const deleteRuleAction = action(async function deleteRuleAction(id: string) {
  const user = await requirePermission("detections.tune");
  await deleteRule(id, user.id);
  done();
});

const keys = <T extends Record<string, string>>(o: T) => Object.keys(o) as [keyof T & string, ...(keyof T & string)[]];
const tuningInput = z.object({
  tenantId: z.string().min(1),
  target: z.string().min(1).max(200),
  kind: z.enum(keys(TUNING_KINDS)),
  field: z.enum(keys(TUNING_FIELDS)).nullable().optional(),
  op: z.enum(keys(TUNING_OPS)).nullable().optional(),
  value: z.string().max(300).nullable().optional(),
  severity: z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]).nullable().optional(),
  reason: z.string().trim().min(1, "Say why").max(1000),
  expiresAt: z.iso.date().nullable().optional(),
});

export const addTuningAction = action(async function addTuningAction(input: z.input<typeof tuningInput>) {
  const user = await requirePermission("detections.tune");
  const t = tuningInput.parse(input);
  await scope(t.tenantId);
  await addTuning({ ...t, kind: t.kind as TuningKind, field: (t.field ?? null) as TuningField | null, op: (t.op ?? null) as TuningOp | null, expiresAt: t.expiresAt ? new Date(`${t.expiresAt}T23:59:59Z`) : null }, user.id);
  done();
});

export const removeTuningAction = action(async function removeTuningAction(id: string) {
  const user = await requirePermission("detections.tune");
  await removeTuning(id, user.id);
  done();
});
