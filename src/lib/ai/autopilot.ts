import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { notify, staffFor } from "@/lib/notifications";
import { getSetting } from "@/lib/settings";
import { severityRank } from "@/lib/severity";
import { CLOSED_STATUSES } from "@/lib/cases/labels";
import { sweepEvidence, type EvidenceSweep } from "@/lib/ai/evidence-sweep";
import { buildFinalAnalysis, type FinalAnalysis } from "@/lib/ai/final-analysis";

// HELIOS works a case on its own, end to end, so nobody has to sit with it:
//   first response (triage and initial containment, lib/ai/first-response)
//   → evidence sweep across the client's own tools (lib/ai/evidence-sweep)
//   → the investigation agent (read-only tools, cited findings, timeline)
//   → the report writer's narrative
//   → the final analysis: root cause, scope, containment, when to lift it,
//     the remediation plan (lib/ai/final-analysis)
//   → the SOC and the client review it.
// People decide only what the rules keep for them: lifting containment,
// remediation that changes access or data, and closing the case.
// A background job picks cases up once first response is done, one at a
// time per worker; a case claims itself, so several workers don't collide.

const STALE_MS = 30 * 60_000;

export async function runAutopilot(now = new Date(), budget = 3) {
  const cfg = await getSetting("ai.autopilot");
  // The kill switch stops every AI agent, this one included.
  if (!cfg.enabled || (await getSetting("ai.killSwitch"))) return 0;
  // A run that died part way (a restart) is picked up again.
  await db.case.updateMany({ where: { analysisStatus: "running", analysisUpdatedAt: { lt: new Date(now.getTime() - STALE_MS) } }, data: { analysisStatus: null } });
  const candidates = await db.case.findMany({
    where: { aiStatus: "completed", analysisStatus: null, status: { notIn: CLOSED_STATUSES }, createdAt: { gte: new Date(now.getTime() - 14 * 86_400_000) } },
    orderBy: { createdAt: "asc" },
    select: { id: true, severity: true },
    take: 25,
  });
  let done = 0;
  for (const c of candidates) {
    if (done >= budget) break;
    if (severityRank(c.severity) < severityRank(cfg.minSeverity)) {
      await db.case.updateMany({ where: { id: c.id, analysisStatus: null }, data: { analysisStatus: "skipped", analysisUpdatedAt: now } });
      continue;
    }
    const claimed = await db.case.updateMany({ where: { id: c.id, analysisStatus: null }, data: { analysisStatus: "running", analysisUpdatedAt: now } });
    if (!claimed.count) continue;
    try {
      await analyseCase(c.id);
    } catch (err) {
      console.error("Autonomous analysis failed", c.id, err);
      await db.case.update({ where: { id: c.id }, data: { analysisStatus: "failed", analysisUpdatedAt: new Date() } });
      await logAction({ caseId: c.id, action: "ai.autopilot_failed", detail: { error: err instanceof Error ? err.message : String(err) } });
    }
    done++;
  }
  return done;
}

// One case, end to end. Safe to run again: a new report version is written.
export async function analyseCase(caseId: string, opts: { refresh?: boolean } = {}) {
  const started = Date.now();
  const { runAgentOnCase } = await import("@/lib/ai/first-response");

  let sweep: EvidenceSweep | null = null;
  try {
    sweep = await sweepEvidence(caseId, { refresh: opts.refresh });
    await db.timelineEntry.create({
      data: {
        caseId,
        occurredAt: new Date(),
        actor: "HELIOS",
        action: "ai.evidence_collected",
        detail: `Collected ${sweep.events} event(s) from the client's sources (${sweep.logTypes.filter((t) => t.events).map((t) => `${t.label.toLowerCase()} ${t.events}`).join(", ") || "none"}); ${sweep.attached} attached as evidence${sweep.gaps.length ? `; not available: ${sweep.gaps.map((g) => g.label.toLowerCase()).join(", ")}` : ""}`,
        evidence: JSON.parse(JSON.stringify({ sweep })),
      },
    });
  } catch (err) {
    console.error("Evidence sweep failed", caseId, err);
  }

  // The investigation agent works the case with what was collected; what it
  // recommends goes through the same containment policy as triage.
  await runAgentOnCase(caseId, "investigator", { trigger: "auto" }).catch((err) => console.error("Investigation failed", caseId, err));
  // The narrative for people, client-readable.
  const narrative = await runAgentOnCase(caseId, "report", { trigger: "auto" })
    .then((run) => (run?.output as { markdown?: string } | null)?.markdown ?? null)
    .catch(() => null);

  const analysis = await buildFinalAnalysis(caseId, sweep, narrative);
  const kase = await db.case.findUniqueOrThrow({ where: { id: caseId }, select: { tenantId: true, title: true, assignedToId: true } });
  const last = await db.caseReport.findFirst({ where: { caseId }, orderBy: { version: "desc" }, select: { version: true } });
  const report = await db.caseReport.create({
    data: {
      caseId,
      tenantId: kase.tenantId,
      version: (last?.version ?? 0) + 1,
      status: "ready",
      verdict: analysis.verdict,
      confidence: analysis.confidence,
      summary: analysis.summary.slice(0, 4000),
      body: JSON.parse(JSON.stringify(analysis)),
      engine: analysis.basedOn?.engine ?? "built-in",
      model: analysis.basedOn?.model ?? null,
    },
  });
  await db.case.update({ where: { id: caseId }, data: { analysisStatus: "ready", analysisUpdatedAt: new Date() } });
  await db.timelineEntry.create({ data: { caseId, occurredAt: new Date(), actor: "HELIOS", action: "ai.final_analysis", detail: `Final analysis v${report.version} ready for review: ${analysis.verdict.replace("_", " ")}, ${Math.round(analysis.confidence * 100)}% confidence; ${analysis.lift.length} lift proposal(s), ${analysis.remediation.length} remediation step(s)`, evidence: { reportId: report.id } } });
  await logAction({ caseId, action: "ai.final_analysis_ready", detail: { reportId: report.id, version: report.version, verdict: analysis.verdict, confidence: analysis.confidence, lift: analysis.lift.length, remediation: analysis.remediation.length, ms: Date.now() - started } });

  // The review is the only step left for people: the SOC and the client.
  const watchers = await db.caseWatcher.findMany({ where: { caseId }, select: { userId: true } });
  const clientAdmins = kase.tenantId ? await db.user.findMany({ where: { tenantId: kase.tenantId, role: "CLIENT_ADMIN", active: true }, select: { id: true } }) : [];
  await notify(
    [...(await staffFor(["SOC_MANAGER", "INCIDENT_RESPONDER"])), ...(kase.assignedToId ? [kase.assignedToId] : []), ...watchers.map((w) => w.userId), ...clientAdmins.map((u) => u.id)],
    {
      kind: "ai",
      title: `Final analysis ready: ${kase.title}`,
      body: `${analysis.summary.slice(0, 300)} ${analysis.lift.length ? `Lifting containment (${analysis.lift.length}) and ` : ""}${analysis.remediation.filter((r) => r.actionId).length} remediation action(s) wait for approval.`,
      caseId,
      actorName: "HELIOS",
    },
  );
  return report;
}

export type { FinalAnalysis };

// The SOC's review of a final analysis. Lifting and remediation are approved
// on their own actions; this records that a person has read and accepted it.
export async function reviewReport(reportId: string, reviewer: { id: string; name: string; isClient: boolean }, note: string) {
  const report = await db.caseReport.findUniqueOrThrow({ where: { id: reportId } });
  const now = new Date();
  if (reviewer.isClient) {
    await db.caseReport.update({ where: { id: reportId }, data: { clientSeenById: reviewer.id, clientSeenByName: reviewer.name, clientSeenAt: now } });
    await logAction({ actorId: reviewer.id, caseId: report.caseId, action: "ai.final_analysis_acknowledged", detail: { reportId, version: report.version } });
    return;
  }
  if (report.status === "reviewed") throw new Error("Already reviewed");
  await db.caseReport.update({ where: { id: reportId }, data: { status: "reviewed", reviewedById: reviewer.id, reviewedByName: reviewer.name, reviewedAt: now, reviewNote: note.trim() || null } });
  await db.case.update({ where: { id: report.caseId }, data: { analysisStatus: "reviewed", analysisUpdatedAt: now } });
  await logAction({ actorId: reviewer.id, caseId: report.caseId, action: "ai.final_analysis_reviewed", detail: { reportId, version: report.version, note: note.trim() || null } });
}
