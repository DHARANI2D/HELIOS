import { randomBytes } from "node:crypto";
import type { Prisma, SecurityTest, UserRole } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { notify, staffFor } from "@/lib/notifications";
import { CHECKS, SOURCE, runExposureCheck, type CheckKey, type Net } from "@/lib/testing/exposure";
import { mergeFindings, finding, severityCounts, type TestFinding } from "@/lib/testing/findings";
import { IMPORT_TOOLS, ImportError, detectTool, parseImport, type ImportTool } from "@/lib/testing/imports";
import { ScopeError, hostOf, inScope, parseTargets, verifyRecord, verifyScope, type Resolver, type ScopeTarget } from "@/lib/testing/scope";

// Security tests on request, under written authorisation:
//   1. someone asks (the client's admin, or the SOC for the client): what,
//      which checks, the window, the rules of engagement;
//   2. the client proves it controls each target (a DNS TXT record);
//   3. the client's admin authorises it, attesting they may permit it, and
//      a HELIOS approver who didn't ask for it authorises it too;
//   4. HELIOS runs it on its own when the window opens, re-checks the proof
//      first, stays in the window, and stops if anyone cancels;
//   5. the report: findings by severity with evidence and how to fix them,
//      with scanner results imported alongside; a re-test in the window
//      confirms fixes.
// Nothing is exploited: HELIOS looks at what is exposed. Deeper tests run
// in established scanners under the same authorisation, and their results
// come in through the import.

export interface TestActor {
  id: string;
  name: string;
  role: UserRole;
  isClient: boolean;
  tenantId: string | null;
}

export class TestError extends Error {}

const MAX_WINDOW_DAYS = 30;
const OPEN = ["requested", "authorised", "queued", "running"];

export const targetsOf = (t: Pick<SecurityTest, "targets">) => (t.targets as unknown as ScopeTarget[]) ?? [];
export const findingsOf = (t: Pick<SecurityTest, "findings">) => (t.findings as unknown as TestFinding[] | null) ?? [];
const json = (v: unknown) => JSON.parse(JSON.stringify(v)) as Prisma.InputJsonValue;

function assertSameClient(actor: TestActor, tenantId: string) {
  if (actor.isClient && actor.tenantId !== tenantId) throw new TestError("Not found");
}

async function clientAdmins(tenantId: string) {
  return (await db.user.findMany({ where: { tenantId, role: "CLIENT_ADMIN", active: true }, select: { id: true } })).map((u) => u.id);
}

export interface TestRequest {
  tenantId: string;
  title: string;
  targets: string;
  checks: CheckKey[];
  rulesOfEngagement: string;
  windowStart: Date;
  windowEnd: Date;
}

export async function requestTest(input: TestRequest, actor: TestActor, now = new Date()) {
  assertSameClient(actor, input.tenantId);
  const tenant = await db.tenant.findUniqueOrThrow({ where: { id: input.tenantId }, select: { id: true, name: true } });
  const title = input.title.trim();
  if (!title) throw new TestError("Give the test a name");
  let targets: ScopeTarget[];
  try {
    targets = parseTargets(input.targets);
  } catch (err) {
    if (err instanceof ScopeError) throw new TestError(err.message);
    throw err;
  }
  const checks = [...new Set(input.checks)].filter((c) => c in CHECKS);
  if (!checks.length) throw new TestError("Pick at least one check");
  if (!input.rulesOfEngagement.trim()) throw new TestError("Write the rules of engagement: who to call, what's out of bounds, any times to avoid");
  if (!(input.windowEnd > input.windowStart)) throw new TestError("The window must end after it starts");
  if (input.windowStart.getTime() < now.getTime() - 3_600_000) throw new TestError("The window can't start in the past");
  if (input.windowEnd.getTime() - input.windowStart.getTime() > MAX_WINDOW_DAYS * 86_400_000) throw new TestError(`A window of at most ${MAX_WINDOW_DAYS} days`);
  if (input.windowStart.getTime() > now.getTime() + 90 * 86_400_000) throw new TestError("The window must start within 90 days");

  const test = await db.securityTest.create({
    data: {
      tenantId: tenant.id,
      title: title.slice(0, 200),
      targets: json(targets),
      checks,
      rulesOfEngagement: input.rulesOfEngagement.trim().slice(0, 5000),
      windowStart: input.windowStart,
      windowEnd: input.windowEnd,
      verifyToken: randomBytes(16).toString("hex"),
      requestedById: actor.id,
      requestedByName: actor.name,
    },
  });
  await logAction({ actorId: actor.id, action: "testing.requested", detail: { testId: test.id, tenantId: tenant.id, targets: targets.map((t) => t.value), checks, window: [input.windowStart.toISOString(), input.windowEnd.toISOString()] } });
  await notify([...(await clientAdmins(tenant.id)), ...(await staffFor(["SOC_MANAGER"]))], {
    kind: "testing",
    title: `Security test requested: ${title}`,
    body: `${tenant.name} · ${targets.length} target(s). Verify the targets and authorise it before ${input.windowStart.toISOString().slice(0, 16).replace("T", " ")} UTC.`,
    href: `/testing/${test.id}`,
    actorName: actor.name,
  }, { exclude: actor.id });
  return test;
}

// Checks the DNS proof for each target; anyone on the test's side can ask.
export async function verifyTest(testId: string, actor: TestActor, dns: Resolver, now = new Date()) {
  const test = await db.securityTest.findUniqueOrThrow({ where: { id: testId } });
  assertSameClient(actor, test.tenantId);
  if (!["requested", "authorised"].includes(test.status)) throw new TestError("Only a test waiting to run can be verified");
  const targets = await verifyScope(targetsOf(test), test.verifyToken, dns, now);
  await db.securityTest.update({ where: { id: testId }, data: { targets: json(targets) } });
  await logAction({ actorId: actor.id, action: "testing.scope_verified", detail: { testId, verified: targets.filter((t) => t.verified).map((t) => t.value), unverified: targets.filter((t) => !t.verified).map((t) => ({ target: t.value, problem: t.problem })) } });
  return targets;
}

export function attestationText(test: Pick<SecurityTest, "title" | "windowStart" | "windowEnd">, tenantName: string, targets: ScopeTarget[]) {
  return `I confirm that ${tenantName} owns or is authorised to permit testing of ${targets.map((t) => t.value).join(", ")}, and authorise HELIOS to run "${test.title}" against them between ${test.windowStart.toISOString().slice(0, 16).replace("T", " ")} and ${test.windowEnd.toISOString().slice(0, 16).replace("T", " ")} UTC under the rules of engagement recorded with it.`;
}

// The client's admin authorises for the client; a HELIOS approver who didn't
// ask for it authorises for HELIOS. Both, with every target verified.
export async function authoriseTest(testId: string, actor: TestActor, opts: { attest?: boolean } = {}, now = new Date()) {
  const test = await db.securityTest.findUniqueOrThrow({ where: { id: testId }, include: { tenant: { select: { name: true } } } });
  assertSameClient(actor, test.tenantId);
  if (test.status !== "requested") throw new TestError(`This test is ${test.status}`);
  if (now >= test.windowEnd) throw new TestError("The window has passed; ask for a new test");
  const targets = targetsOf(test);
  const unverified = targets.filter((t) => !t.verified);
  if (unverified.length) throw new TestError(`Verify every target first: ${unverified.map((t) => t.value).join(", ")}`);

  const data: Prisma.SecurityTestUpdateInput = {};
  if (actor.isClient) {
    if (actor.role !== "CLIENT_ADMIN") throw new TestError("Only the client's admin can authorise a test for the client");
    if (test.clientAuthorisedAt) throw new TestError("Already authorised for the client");
    if (!opts.attest) throw new TestError("Confirm that you may authorise testing of these assets");
    Object.assign(data, { clientAuthorisedById: actor.id, clientAuthorisedByName: actor.name, clientAuthorisedAt: now, clientAttestation: attestationText(test, test.tenant.name, targets) });
  } else {
    if (actor.role !== "ADMIN" && actor.role !== "SOC_MANAGER") throw new TestError("A HELIOS approver (SOC manager or admin) authorises for HELIOS");
    if (test.heliosAuthorisedAt) throw new TestError("Already authorised for HELIOS");
    if (test.requestedById === actor.id) throw new TestError("Someone other than the person who asked for it authorises it for HELIOS");
    Object.assign(data, { heliosAuthorisedById: actor.id, heliosAuthorisedByName: actor.name, heliosAuthorisedAt: now });
  }
  const both = (actor.isClient ? !!test.heliosAuthorisedAt : !!test.clientAuthorisedAt);
  if (both) data.status = "authorised";
  const updated = await db.securityTest.update({ where: { id: testId }, data });
  await logAction({ actorId: actor.id, action: actor.isClient ? "testing.client_authorised" : "testing.helios_authorised", detail: { testId, tenantId: test.tenantId, attestation: actor.isClient ? updated.clientAttestation : undefined, complete: both } });
  if (both) {
    await notify([...(await clientAdmins(test.tenantId)), ...(await staffFor(["SOC_MANAGER"])), ...(test.requestedById ? [test.requestedById] : [])], {
      kind: "testing",
      title: `Security test authorised: ${test.title}`,
      body: `It runs on its own from ${test.windowStart.toISOString().slice(0, 16).replace("T", " ")} UTC. Anyone on either side can stop it.`,
      href: `/testing/${test.id}`,
      actorName: actor.name,
    }, { exclude: actor.id });
  }
  return updated;
}

// Rejecting before it runs, or stopping it at any point: either side.
export async function closeTest(testId: string, actor: TestActor, reason: string) {
  const test = await db.securityTest.findUniqueOrThrow({ where: { id: testId } });
  assertSameClient(actor, test.tenantId);
  if (!OPEN.includes(test.status) && !(test.status === "completed")) throw new TestError(`This test is already ${test.status}`);
  if (!reason.trim()) throw new TestError("Say why");
  const status = test.status === "requested" ? "rejected" : "cancelled";
  await db.securityTest.update({ where: { id: testId }, data: { status, closedByName: actor.name, closedReason: reason.trim().slice(0, 1000) } });
  await logAction({ actorId: actor.id, action: `testing.${status}`, detail: { testId, reason: reason.trim() } });
  await notify([...(await clientAdmins(test.tenantId)), ...(await staffFor(["SOC_MANAGER"])), ...(test.requestedById ? [test.requestedById] : [])], { kind: "testing", title: `Security test ${status}: ${test.title}`, body: reason.trim().slice(0, 300), href: `/testing/${test.id}`, actorName: actor.name }, { exclude: actor.id });
}

// A re-test inside the window (after fixes, say).
export async function retest(testId: string, actor: TestActor, now = new Date()) {
  const test = await db.securityTest.findUniqueOrThrow({ where: { id: testId } });
  assertSameClient(actor, test.tenantId);
  if (!["completed", "authorised"].includes(test.status)) throw new TestError(`This test is ${test.status}`);
  if (now < test.windowStart || now >= test.windowEnd) throw new TestError("Only inside the authorised window");
  await db.securityTest.update({ where: { id: testId }, data: { status: "queued" } });
  await logAction({ actorId: actor.id, action: "testing.retest_requested", detail: { testId } });
}

// The background job: tests whose window is open and that are due.
export async function runDueTests(net: Net, now = new Date(), budget = 1) {
  // A run that died part way (a restart) goes back in the queue.
  await db.securityTest.updateMany({ where: { status: "running", startedAt: { lt: new Date(now.getTime() - 60 * 60_000) } }, data: { status: "queued" } });
  // A window that closed before the test ran.
  const missed = await db.securityTest.findMany({ where: { status: { in: ["authorised", "queued"] }, windowEnd: { lte: now } }, select: { id: true, runs: true } });
  for (const m of missed) await db.securityTest.update({ where: { id: m.id }, data: m.runs ? { status: "completed" } : { status: "cancelled", closedByName: "HELIOS", closedReason: "The window closed before the test could run" } });

  const due = await db.securityTest.findMany({ where: { windowStart: { lte: now }, windowEnd: { gt: now }, OR: [{ status: "authorised", runs: 0 }, { status: "queued" }] }, orderBy: { windowStart: "asc" }, take: 5 });
  let done = 0;
  for (const t of due) {
    if (done >= budget) break;
    const claimed = await db.securityTest.updateMany({ where: { id: t.id, status: t.status }, data: { status: "running", startedAt: new Date() } });
    if (!claimed.count) continue;
    await runTest(t.id, net).catch(async (err) => {
      console.error("Security test failed", t.id, err);
      await db.securityTest.update({ where: { id: t.id }, data: { status: "completed", finishedAt: new Date(), probes: json([{ at: new Date().toISOString(), target: "-", check: "run", result: `failed: ${err instanceof Error ? err.message : String(err)}` }]) } });
    });
    done++;
  }
  return done;
}

export async function runTest(testId: string, net: Net) {
  const test = await db.securityTest.findUniqueOrThrow({ where: { id: testId }, include: { tenant: { select: { name: true } } } });
  await logAction({ action: "testing.started", detail: { testId, run: test.runs + 1, targets: targetsOf(test).map((t) => t.value) } });
  // The proof must still hold when the test runs.
  const targets = await verifyScope(targetsOf(test), test.verifyToken, net);
  const lost = targets.filter((t) => !t.verified);
  const shouldStop = async () => {
    const t = await db.securityTest.findUnique({ where: { id: testId }, select: { status: true, windowEnd: true } });
    if (!t || t.status !== "running") return "stopped by a person";
    if (new Date() >= t.windowEnd) return "the authorised window closed";
    return null;
  };
  const { findings, probes, stopped } = await runExposureCheck(targets, { checks: test.checks as CheckKey[], net, shouldStop });
  // Only what this run actually looked at can be confirmed fixed.
  const checked = new Set(targets.filter((t) => t.verified).flatMap((t) => [hostOf(t), ...t.addresses]));
  const merged = mergeFindings(findingsOf(test), findings, (f) => !stopped && f.source === SOURCE && checked.has(f.target.toLowerCase()), new Date());
  const current = await db.securityTest.findUniqueOrThrow({ where: { id: testId }, select: { status: true } });
  await db.securityTest.update({
    where: { id: testId },
    data: {
      status: current.status === "cancelled" ? "cancelled" : "completed",
      runs: { increment: 1 },
      finishedAt: new Date(),
      targets: json(targets),
      findings: json(merged),
      probes: json([...lost.map((t) => ({ at: new Date().toISOString(), target: t.value, check: "scope", result: `skipped: ${t.problem}` })), ...probes].slice(0, 2000)),
    },
  });
  const counts = severityCounts(merged);
  await logAction({ action: "testing.finished", detail: { testId, probes: probes.length, findings: findings.length, open: counts, skipped: lost.map((t) => t.value), stopped } });
  await notify([...(await clientAdmins(test.tenantId)), ...(await staffFor(["SOC_MANAGER"])), ...(test.requestedById ? [test.requestedById] : [])], {
    kind: "testing",
    title: `Security test report ready: ${test.title}`,
    body: `${test.tenant.name}: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low open${stopped ? ` (stopped: ${stopped})` : ""}${lost.length ? `; ${lost.length} target(s) skipped: proof no longer found` : ""}.`,
    href: `/testing/${test.id}`,
    actorName: "HELIOS",
  });
}

// A scanner's report, kept to the test's verified targets.
export async function importResults(testId: string, actor: TestActor, file: { name: string; text: string; tool?: ImportTool | null }) {
  const test = await db.securityTest.findUniqueOrThrow({ where: { id: testId } });
  assertSameClient(actor, test.tenantId);
  if (!["authorised", "queued", "running", "completed"].includes(test.status)) throw new TestError("Results can be added once the test is authorised");
  if (file.text.length > 20 * 1024 * 1024) throw new TestError("The report is over 20 MB; split it by host");
  const tool = file.tool ?? detectTool(file.name, file.text);
  if (!tool) throw new TestError(`Couldn't tell which scanner wrote ${file.name}; pick it`);
  let parsed;
  try {
    parsed = parseImport(tool, file.text);
  } catch (err) {
    if (err instanceof ImportError) throw new TestError(err.message);
    throw err;
  }
  const targets = targetsOf(test);
  const kept = parsed.filter((f) => f.target && inScope(targets, f.target));
  const now = new Date();
  const fresh = kept.map((f) => finding(f, now));
  const source = fresh[0]?.source ?? IMPORT_TOOLS[tool].label;
  // A report speaks for the hosts it covers, not the rest of the scope.
  const reported = new Set(kept.map((f) => f.target.toLowerCase()));
  const merged = mergeFindings(findingsOf(test), fresh, (f) => f.source === source && reported.has(f.target.toLowerCase()), now);
  const record = { tool, file: file.name.slice(0, 200), at: now.toISOString(), by: actor.name, kept: kept.length, outOfScope: parsed.length - kept.length };
  await db.securityTest.update({ where: { id: testId }, data: { findings: json(merged), imports: json([...((test.imports as unknown[] | null) ?? []), record]) } });
  await logAction({ actorId: actor.id, action: "testing.results_imported", detail: { testId, ...record } });
  return record;
}

// Fixed, accepted (a risk the client chooses to carry, with the reason), or open again.
export async function setFindingStatus(testId: string, findingId: string, status: TestFinding["status"], note: string, actor: TestActor) {
  const test = await db.securityTest.findUniqueOrThrow({ where: { id: testId } });
  assertSameClient(actor, test.tenantId);
  if (status === "accepted" && !note.trim()) throw new TestError("Say why the risk is accepted");
  if (status === "accepted" && !actor.isClient && actor.role !== "ADMIN" && actor.role !== "SOC_MANAGER") throw new TestError("A risk is accepted by the client's admin or a SOC manager");
  const fs = findingsOf(test);
  const f = fs.find((x) => x.id === findingId);
  if (!f) throw new TestError("Not found");
  const next = fs.map((x) => (x.id === findingId ? { ...x, status, statusNote: note.trim().slice(0, 1000) || null } : x));
  await db.securityTest.update({ where: { id: testId }, data: { findings: json(next) } });
  await logAction({ actorId: actor.id, action: "testing.finding_status", detail: { testId, findingId, title: f.title, target: f.target, from: f.status, to: status, note: note.trim() || null } });
}

export { verifyRecord };
