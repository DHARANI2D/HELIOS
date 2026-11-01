"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { db } from "@/lib/db";
import { requirePermission, type SessionUser } from "@/lib/session";
import { action } from "@/lib/action";
import { CHECKS, type CheckKey } from "@/lib/testing/exposure";
import { IMPORT_TOOLS, type ImportTool } from "@/lib/testing/imports";
import { liveNet } from "@/lib/testing/net";
import { authoriseTest, closeTest, importResults, requestTest, retest, setFindingStatus, verifyTest, type TestActor } from "@/lib/testing/service";
import { can, type Permission } from "@/lib/rbac";

// Security tests: every call re-checks the permission, and a client user
// only ever reaches their own client's tests.

const actorOf = (u: SessionUser): TestActor => ({ id: u.id, name: u.name ?? u.email ?? "user", role: u.role, isClient: u.isClient, tenantId: u.tenantId });

async function testActor(testId: string, ...permissions: Permission[]) {
  const user = await requirePermission(...permissions);
  const test = await db.securityTest.findUnique({ where: { id: testId }, select: { tenantId: true } });
  if (!test || (user.isClient && user.tenantId !== test.tenantId)) throw new Error("Not found");
  return actorOf(user);
}

const done = (testId?: string) => {
  revalidatePath("/testing");
  if (testId) revalidatePath(`/testing/${testId}`);
};

const requestSchema = z.object({
  tenantId: z.string().max(64),
  title: z.string().trim().min(1).max(200),
  targets: z.string().max(5000),
  checks: z.array(z.enum(Object.keys(CHECKS) as [CheckKey, ...CheckKey[]])).min(1),
  rulesOfEngagement: z.string().trim().min(1).max(5000),
  windowStart: z.string().datetime({ offset: true }),
  windowEnd: z.string().datetime({ offset: true }),
});

export const requestTestAction = action(async function requestTestAction(input: z.input<typeof requestSchema>) {
  const user = await requirePermission("testing.request");
  const s = requestSchema.parse(input);
  const tenantId = user.isClient ? user.tenantId : s.tenantId;
  if (!tenantId) throw new Error("Pick the client");
  const test = await requestTest({ ...s, tenantId, windowStart: new Date(s.windowStart), windowEnd: new Date(s.windowEnd) }, actorOf(user));
  done();
  return { id: test.id };
});

export const verifyTestAction = action(async function verifyTestAction(testId: string) {
  const actor = await testActor(testId, "testing.view");
  const targets = await verifyTest(testId, actor, liveNet);
  done(testId);
  return { verified: targets.filter((t) => t.verified).length, total: targets.length };
});

export const authoriseTestAction = action(async function authoriseTestAction(testId: string, attest: boolean) {
  const actor = await testActor(testId, "testing.authorise");
  const t = await authoriseTest(testId, actor, { attest });
  done(testId);
  return { status: t.status };
});

export const closeTestAction = action(async function closeTestAction(testId: string, reason: string) {
  // Whoever may ask for a test or authorise one may also stop it.
  const user = await requirePermission("testing.view");
  if (!can(user, "testing.request") && !can(user, "testing.authorise")) throw new Error("Not allowed");
  const actor = await testActor(testId, "testing.view");
  await closeTest(testId, actor, z.string().max(1000).parse(reason));
  done(testId);
});

export const retestAction = action(async function retestAction(testId: string) {
  const actor = await testActor(testId, "testing.request");
  await retest(testId, actor);
  done(testId);
});

export const importResultsAction = action(async function importResultsAction(testId: string, file: { name: string; text: string; tool: string | null }) {
  const actor = await testActor(testId, "testing.request");
  const tool = file.tool && file.tool in IMPORT_TOOLS ? (file.tool as ImportTool) : null;
  const r = await importResults(testId, actor, { name: String(file.name), text: String(file.text), tool });
  done(testId);
  return r;
});

export const setFindingStatusAction = action(async function setFindingStatusAction(testId: string, findingId: string, status: "open" | "fixed" | "accepted", note: string) {
  const actor = await testActor(testId, "testing.request");
  await setFindingStatus(testId, z.string().max(64).parse(findingId), z.enum(["open", "fixed", "accepted"]).parse(status), z.string().max(1000).parse(note ?? ""), actor);
  done(testId);
});
