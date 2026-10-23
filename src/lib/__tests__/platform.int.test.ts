import { beforeAll, describe, expect, it } from "vitest";

import { db } from "@/lib/db";
import { logAction, verifyAuditChain } from "@/lib/audit";
import { DEFAULT_PLAYBOOKS } from "@/lib/playbooks/defaults";
import { decideExecution } from "@/lib/playbooks/engine";
import { runSimulation } from "@/lib/siem/simulation";
import { runScenario } from "@/lib/governance/simulator";
import { SAMPLE_INVESTIGATION } from "@/lib/investigations/samples";
import { runInvestigationPipeline, startInvestigation } from "@/lib/investigations/service";
import { buildSampleEmail } from "@/lib/forensics/samples";
import { analyzeSubmission } from "@/lib/forensics/service";

// End-to-end against a real Postgres. Truncates every table, so it only runs
// when RUN_DB_TESTS=1 and DATABASE_URL points at a database whose name ends
// in "_test" (CI provisions helios_test).
const dbUrl = process.env.DATABASE_URL ?? "";
const enabled = process.env.RUN_DB_TESTS === "1" && /\/[\w-]*_test(\?|$)/.test(dbUrl);

process.env.FORENSICS_DNS_LOOKUPS = "false";
process.env.INVESTIGATIONS_ENGINE = "heuristic";

describe.skipIf(!enabled)("HELIOS platform (integration)", () => {
  let adminId: string;

  beforeAll(async () => {
    const tables = await db.$queryRaw<Array<{ tablename: string }>>`SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> '_prisma_migrations'`;
    await db.$executeRawUnsafe(`TRUNCATE ${tables.map((t) => `"${t.tablename}"`).join(", ")} RESTART IDENTITY CASCADE`);
    const admin = await db.user.create({ data: { email: "admin@test.local", name: "Test Admin", role: "ADMIN" } });
    adminId = admin.id;
    for (const pb of DEFAULT_PLAYBOOKS) {
      await db.playbook.create({
        data: {
          name: pb.name,
          description: pb.description,
          triggerCondition: pb.triggerCondition,
          autoExecute: pb.autoExecute,
          requireApproval: pb.requireApproval,
          priority: pb.priority,
          actions: { create: pb.actions.map((a, i) => ({ name: a.name, actionType: a.actionType, parameters: a.parameters as never, order: i + 1 })) },
        },
      });
    }
  });

  it("detects simulated attacks and correlates repeats into existing cases", async () => {
    const first = await runSimulation({ tactics: ["Credential Access"] }, adminId);
    expect(first.summary.casesCreated).toBeGreaterThan(0);
    expect(first.summary.newDetections).toBeGreaterThan(0);

    const second = await runSimulation({ tactics: ["Credential Access"] }, adminId);
    expect(second.summary.casesCreated).toBe(0);
    expect(second.summary.casesUpdated).toBeGreaterThan(0);

    const mapped = await db.caseMitreTechnique.count();
    expect(mapped).toBeGreaterThan(0);
  });

  it("gates containment playbooks behind approval and executes on approve", async () => {
    const pending = await db.playbookExecution.findFirst({
      where: { status: "PENDING_APPROVAL", playbook: { name: { startsWith: "Contain ransomware" } } },
    });
    expect(pending).not.toBeNull();
    const kase = await db.case.findUniqueOrThrow({ where: { id: pending!.caseId } });
    expect(["AWAITING_APPROVAL", "CONTAINED"]).toContain(kase.status);

    const done = await decideExecution(pending!.id, "approved", adminId, "integration test");
    expect(done.status).toBe("SUCCEEDED");
    const after = await db.case.findUniqueOrThrow({ where: { id: pending!.caseId }, include: { timeline: true } });
    expect(after.status).toBe("CONTAINED");
    expect(after.timeline.some((t) => t.action === "playbook.isolate_host")).toBe(true);
    expect(await db.playbookApproval.count({ where: { executionId: pending!.id, decision: "approved" } })).toBe(1);
  });

  it("runs an investigation end to end on the deterministic engine", async () => {
    const { caseId, eventCount } = await startInvestigation({
      title: SAMPLE_INVESTIGATION.title,
      alertDetails: SAMPLE_INVESTIGATION.alertDetails,
      files: [],
      pastedLogs: SAMPLE_INVESTIGATION.logs,
      actorId: adminId,
    });
    expect(eventCount).toBe(21);
    await runInvestigationPipeline(caseId);

    const kase = await db.case.findUniqueOrThrow({ where: { id: caseId }, include: { mitreTechniques: true, _count: { select: { events: true, detections: true } } } });
    const meta = kase.metadata as { pipeline: { status: string } };
    expect(meta.pipeline.status).toBe("completed");
    expect(kase.verdict).toBe("malicious");
    expect(kase.severity).toBe("CRITICAL");
    expect(kase._count.events).toBe(21);
    expect(kase._count.detections).toBeGreaterThanOrEqual(8);
    expect(kase.mitreTechniques.map((t) => t.techniqueId)).toContain("T1003.001");
  });

  it("analyzes the sample phishing email into a malicious case with IOCs", async () => {
    const { caseId, verdict } = await analyzeSubmission({ ...buildSampleEmail(), detonate: false, actorId: adminId });
    expect(verdict).toBe("malicious");
    const iocs = await db.caseIndicator.findMany({ where: { caseId }, include: { indicator: true } });
    expect(iocs.some((i) => i.role === "sender" && i.indicator.value === "security@microsoft-support.example.cc")).toBe(true);
    expect(iocs.some((i) => i.indicator.type === "FILE_HASH")).toBe(true);
  });

  it("files governance scenarios as cases mapped to ATT&CK", async () => {
    const result = await runScenario("data_exfiltration", adminId);
    expect(result.revoked).toBe(true);
    const kase = await db.case.findUniqueOrThrow({ where: { id: result.caseId }, include: { mitreTechniques: true } });
    expect(kase.mitreTechniques.map((t) => t.techniqueId)).toEqual(["T1567"]);
    expect((await db.agent.findUniqueOrThrow({ where: { id: result.agentId } })).status).toBe("REVOKED");
  });

  it("keeps the audit chain intact under concurrent writes and detects tampering", async () => {
    await Promise.all(Array.from({ length: 20 }, (_, i) => logAction({ action: "test.concurrent", detail: { i, at: new Date() } })));
    const ok = await verifyAuditChain();
    expect(ok.valid).toBe(true);
    expect(ok.checked).toBeGreaterThan(20);

    const victim = await db.auditLog.findFirstOrThrow({ where: { action: "test.concurrent" }, orderBy: { seq: "asc" } });
    await db.$executeRaw`UPDATE audit_logs SET detail = '{"i": 999}'::jsonb WHERE id = ${victim.id}`;
    const broken = await verifyAuditChain();
    expect(broken.valid).toBe(false);
    expect(broken.brokenAt).toMatchObject({ seq: victim.seq, reason: "hash_mismatch" });
  });

  it("refuses to delete cases that have audit history", async () => {
    const kase = await db.case.findFirstOrThrow({ where: { auditLogs: { some: {} } } });
    await expect(db.case.delete({ where: { id: kase.id } })).rejects.toThrow();
  });
});
