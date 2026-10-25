import { createServer, type IncomingMessage } from "node:http";
import { createElement } from "react";
import { renderToBuffer } from "@react-pdf/renderer";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { UserRole } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction, verifyAuditChain } from "@/lib/audit";
import { DEFAULT_PLAYBOOKS } from "@/lib/playbooks/defaults";
import { decideExecution } from "@/lib/playbooks/engine";
import { runSimulation } from "@/lib/__tests__/fixtures/siem/simulation";
import { buildScenarios } from "@/lib/__tests__/fixtures/governance/scenarios";
import { agentForToken, issueAgentIdentity } from "@/lib/governance/agents";
import { evaluateAgentAction } from "@/lib/governance/runtime";
import { createCase } from "@/lib/cases/writer";
import { completeManualAction, decideResponseAction, performResponseAction, recordResponseAction, requestAnalystAction } from "@/lib/response/service";
import { addAllowlistEntry, rulebookVerdict, saveDraft, signRulebook } from "@/lib/rulebook/service";
import { escalatePendingApprovals } from "@/lib/rulebook/escalation";
import { resolveForClient } from "@/lib/ai/gateway";
import { loadProfile } from "@/lib/ai/resolve";
import { onboardIntegration } from "@/lib/integrations/service";
import { signPayload } from "@/lib/integrations/dispatch";
import { invalidateCatalog } from "@/lib/integrations/tools";
import { ingestTelemetry } from "@/lib/siem/service";
import { importFeed } from "@/lib/threat-intel/feeds";
import { CATALOG_TOOLS } from "../../../prisma/seed-data/tools";
import { buildEvtx } from "@/lib/__tests__/fixtures/evtx-builder";
import { SAMPLE_INVESTIGATION } from "@/lib/__tests__/fixtures/investigations";
import { runInvestigationPipeline, startInvestigation } from "@/lib/investigations/service";
import { buildSampleEmail } from "@/lib/__tests__/fixtures/forensics";
import { analyzeSubmission } from "@/lib/forensics/service";
import { findRelatedCases } from "@/lib/cases/related";
import { gatherEvidence } from "@/lib/ai/evidence";
import { getSetting } from "@/lib/settings";
import { platformSecret, platformSecretStatus, storePlatformSecret } from "@/lib/platform-secrets";
import { adoptAsTestEnvironment } from "../../../prisma/seed-test";
import { CaseReportPdf, loadCaseReport } from "@/lib/pdf/case-report";
import { issueApiToken, revokeApiToken } from "@/lib/api/tokens";
import * as meRoute from "@/app/api/v1/me/route";
import * as casesRoute from "@/app/api/v1/cases/route";
import * as caseRoute from "@/app/api/v1/cases/[id]/route";
import * as commentsRoute from "@/app/api/v1/cases/[id]/comments/route";
import { calculateQuote } from "@/lib/pricing/calculator";
import { loadPricingContext } from "@/lib/pricing/service";
import { clientStackConfig } from "@/lib/pricing/client-stack";
import { createQuote } from "@/lib/pricing/quotes";
import { reviewUpgrades } from "@/lib/pricing/upgrades";

// End-to-end against a real Postgres. Truncates every table, so it only runs
// when RUN_DB_TESTS=1 and DATABASE_URL points at a database whose name ends
// in "_test" (CI provisions helios_test).
const dbUrl = process.env.DATABASE_URL ?? "";
const enabled = process.env.RUN_DB_TESTS === "1" && /\/[\w-]*_test(\?|$)/.test(dbUrl);

process.env.FORENSICS_DNS_LOOKUPS = "false";
process.env.INVESTIGATIONS_ENGINE = "heuristic";

// A local stand-in for the client's automation / firewall feed host.
const received: Array<{ path: string; headers: IncomingMessage["headers"]; body: string }> = [];
let feedBody = "";
const stub = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    received.push({ path: req.url ?? "", headers: req.headers, body });
    if (req.url === "/feed.txt") {
      res.writeHead(200, { "content-type": "text/plain" }).end(feedBody);
      return;
    }
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ ok: true }));
  });
});
let stubUrl = "";

describe.skipIf(!enabled)("HELIOS platform (integration)", () => {
  let adminId: string;

  afterAll(() => {
    stub.close();
  });

  beforeAll(async () => {
    const tables = await db.$queryRaw<Array<{ tablename: string }>>`SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> '_prisma_migrations'`;
    await db.$executeRawUnsafe(`TRUNCATE ${tables.map((t) => `"${t.tablename}"`).join(", ")} RESTART IDENTITY CASCADE`);
    const admin = await db.user.create({ data: { email: "admin@test.local", name: "Test Admin", role: "ADMIN" } });
    adminId = admin.id;
    for (const t of CATALOG_TOOLS) await db.catalogTool.create({ data: t });
    invalidateCatalog();
    await new Promise<void>((resolve) => stub.listen(0, "127.0.0.1", resolve));
    stubUrl = `http://127.0.0.1:${(stub.address() as AddressInfo).port}`;
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

    // The repeat lands on the existing cases; a finding only the combined
    // window reveals (e.g. spraying across both runs) may open a new one, but
    // never a second case for the same risk object.
    const second = await runSimulation({ tactics: ["Credential Access"] }, adminId);
    expect(second.summary.casesUpdated).toBeGreaterThan(0);
    expect(second.summary.caseIds).toEqual(expect.arrayContaining(first.summary.caseIds));
    const siem = await db.case.findMany({ where: { sourceType: "SIEM_ALERT" }, select: { metadata: true } });
    const objects = siem.map((c) => (c.metadata as { riskObject?: string }).riskObject);
    expect(new Set(objects).size).toBe(objects.length);

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
    // No response connector: isolation is left to a person, never claimed.
    expect(after.status).not.toBe("CONTAINED");
    const isolate = after.timeline.find((t) => t.action === "playbook.isolate_host");
    expect(isolate?.detail).toMatch(/no response connector/);
    expect(await db.endpoint.count({ where: { isolated: true } })).toBe(0);
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
    // The report points at the playbook that fits (credential dumping on a host).
    expect((kase.metadata as { report: string }).report).toMatch(/### Playbooks in HELIOS\n- \*\*Contain ransomware \/ credential dumping host\*\* — .*Covers T1003/);
  });

  it("investigates an uploaded Windows event log", async () => {
    const t = (s: number) => new Date(Date.UTC(2026, 9, 20, 8, 0, s));
    const security = "Microsoft-Windows-Security-Auditing";
    const evtx = buildEvtx([
      // An hour of routine service logons the evidence window must look past.
      ...Array.from({ length: 100 }, (_, i) => ({ provider: security, eventId: 4624, time: new Date(Date.UTC(2026, 9, 20, 7, 0, i * 30)), computer: "DC-01.corp.test", data: { TargetUserName: "svc-backup", IpAddress: "10.0.0.5", LogonType: "3" } })),
      ...Array.from({ length: 12 }, (_, i) => ({ provider: security, eventId: 4625, time: t(i * 5), computer: "DC-01.corp.test", data: { TargetUserName: "alice", IpAddress: "198.51.100.40", LogonType: "3" } })),
      { provider: security, eventId: 4624, time: t(70), computer: "DC-01.corp.test", data: { TargetUserName: "alice", IpAddress: "198.51.100.40", LogonType: "10" } },
      { provider: security, eventId: 1102, time: t(90), computer: "DC-01.corp.test", data: { TargetUserName: "alice" } },
    ]);
    const { caseId, eventCount } = await startInvestigation({ title: "Logon storm on DC-01", alertDetails: "", files: [{ name: "Security.evtx", bytes: evtx }], actorId: adminId });
    expect(eventCount).toBe(114);
    await runInvestigationPipeline(caseId);
    const kase = await db.case.findUniqueOrThrow({ where: { id: caseId }, include: { detections: true, mitreTechniques: true, indicators: { include: { indicator: true } } } });
    expect(kase.detections.map((d) => d.ruleId)).toEqual(expect.arrayContaining(["investigation:brute_force", "investigation:log_clearing", "investigation:external_rdp_logon"]));
    expect(kase.severity).toBe("CRITICAL");
    expect(kase.mitreTechniques.map((m) => m.techniqueId)).toEqual(expect.arrayContaining(["T1110.001", "T1070.001"]));
    expect(kase.indicators.some((i) => i.indicator.value === "198.51.100.40")).toBe(true);

    // The first responder's evidence leads with what the rules flagged.
    const events = (await gatherEvidence(caseId)).refs.filter((r) => r.kind === "event").map((r) => r.text);
    expect(events).toHaveLength(80);
    expect(events.filter((t) => t.includes("auth_failure"))).toHaveLength(12);
    expect(events.some((t) => t.includes("log_cleared"))).toBe(true);
    expect(events.some((t) => t.includes("user=svc-backup"))).toBe(true); // the rest is filled with context
  });

  it("exports incident reports, without AI working notes for clients", async () => {
    const kase = await db.case.findFirstOrThrow({ where: { sourceType: "SOC_INVESTIGATION" }, orderBy: { createdAt: "asc" } });
    await db.aiRun.create({ data: { caseId: kase.id, agentKey: "triage", trigger: "auto", engine: "built-in", status: "succeeded", output: { verdict: "true_positive", severity: "high", confidence: 0.9, summary: "Internal triage note", key_findings: [], recommended_actions: [], analyst_next_steps: [], escalation_tier: 2 } } });
    const staff = await loadCaseReport(kase.id, "staff");
    const client = await loadCaseReport(kase.id, "client");
    expect(staff.kase.aiRuns).toHaveLength(1);
    expect(client.kase.aiRuns).toBeUndefined();
    const company = await getSetting("company.profile");
    for (const report of [staff, client]) {
      const pdf = await renderToBuffer(createElement(CaseReportPdf, { report, company }) as Parameters<typeof renderToBuffer>[0]);
      expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    }
  });

  it("links a repeat intrusion to the earlier case and cites it in the RCA", async () => {
    const first = await db.case.findFirstOrThrow({ where: { sourceType: "SOC_INVESTIGATION" }, orderBy: { createdAt: "asc" } });
    const { caseId } = await startInvestigation({
      title: "Repeat activity on WS-FIN-042",
      alertDetails: "",
      files: [],
      pastedLogs: SAMPLE_INVESTIGATION.logs,
      actorId: adminId,
    });
    await runInvestigationPipeline(caseId);

    const related = await findRelatedCases(caseId);
    const link = related.find((r) => r.id === first.id);
    expect(link).toBeDefined();
    expect(link!.reasons).toEqual(expect.arrayContaining(["Same host WS-FIN-042.acme.local", "Shared ip 185.220.101.5"]));
    expect(related.some((r) => r.reasons.some((x) => /system/i.test(x)))).toBe(false);

    const kase = await db.case.findUniqueOrThrow({ where: { id: caseId } });
    expect(kase.rootCauseNarrative).toContain("overlaps");
    expect(kase.rootCauseNarrative).toContain(first.title);
  });

  it("analyzes the sample phishing email into a malicious case with IOCs", async () => {
    const { caseId, verdict } = await analyzeSubmission({ ...buildSampleEmail(), detonate: false, actorId: adminId });
    expect(verdict).toBe("malicious");
    const iocs = await db.caseIndicator.findMany({ where: { caseId }, include: { indicator: true } });
    expect(iocs.some((i) => i.role === "sender" && i.indicator.value === "security@microsoft-support.example.cc")).toBe(true);
    expect(iocs.some((i) => i.indicator.type === "FILE_HASH")).toBe(true);
  });

  it("gates governed AI agents through the live runtime", async () => {
    const tenant = await db.tenant.create({ data: { name: "Test · Governance", slug: "test-governance" } });
    const { agent, token } = await issueAgentIdentity("test-gov-agent", adminId, tenant.id);
    expect((await agentForToken(`Bearer ${token}`))?.id).toBe(agent.id);
    expect(await agentForToken("Bearer hga_wrong")).toBeNull();

    const [read, exfil] = buildScenarios().find((s) => s.id === "data_exfiltration")!.events;
    const allowed = await evaluateAgentAction(agent, read, "production");
    expect(allowed).toMatchObject({ decision: "ALLOW", caseId: null });
    const denied = await evaluateAgentAction(await db.agent.findUniqueOrThrow({ where: { id: agent.id } }), exfil, "production");
    expect(denied).toMatchObject({ decision: "DENY", layer: "DLP", revoked: false });
    expect(denied.trust).toBeLessThan(allowed.trust);
    const kase = await db.case.findUniqueOrThrow({ where: { id: denied.caseId! }, include: { mitreTechniques: true } });
    expect(kase).toMatchObject({ sourceType: "AGENT_GOVERNANCE", tenantId: tenant.id });
    expect(kase.mitreTechniques.map((t) => t.techniqueId)).toEqual(["T1567"]);

    const breach = await evaluateAgentAction(await db.agent.findUniqueOrThrow({ where: { id: agent.id } }), { name: "ESCALATE_OWN_PRIVILEGE" }, "production");
    expect(breach).toMatchObject({ decision: "DENY", layer: "CONSTITUTION", revoked: true, caseId: denied.caseId });
    expect((await db.case.findUniqueOrThrow({ where: { id: denied.caseId! } })).status).toBe("CONTAINED");
    const after = await evaluateAgentAction(await db.agent.findUniqueOrThrow({ where: { id: agent.id } }), read, "production");
    expect(after).toMatchObject({ decision: "DENY", layer: "IDENTITY" });
    expect(await db.securityEvent.count({ where: { platform: "helios-governance", tenantId: tenant.id } })).toBe(3);
  });

  it("applies the client's plan SLA and none without a plan", async () => {
    const plan = await db.servicePlan.create({ data: { key: "test-plan", name: "Test plan", coverage: "24x7", ackMinutes: { CRITICAL: 30 }, containMinutes: {}, features: {} } });
    const onPlan = await db.tenant.create({ data: { name: "Test · Planned", slug: "test-planned", planId: plan.id } });
    const noPlan = await db.tenant.create({ data: { name: "Test · Unplanned", slug: "test-unplanned" } });
    const a = await createCase({ sourceType: "SIEM_ALERT", title: "SLA test", severity: "CRITICAL", tenantId: onPlan.id, deferPipelines: true });
    const b = await createCase({ sourceType: "SIEM_ALERT", title: "SLA test", severity: "CRITICAL", tenantId: noPlan.id, deferPipelines: true });
    // Due 30 min after creation (createdAt is stamped by the database a moment later).
    expect(Math.abs(a.slaDueAt!.getTime() - a.createdAt.getTime() - 30 * 60_000)).toBeLessThan(1000);
    expect(b.slaDueAt).toBeNull();
  });

  it("leaves actions without a connector to a person, and counts them only once done", async () => {
    const tenant = await db.tenant.create({ data: { name: "Test · Manual", slug: "test-manual" } });
    const kase = await createCase({ sourceType: "SIEM_ALERT", title: "Manual containment", severity: "HIGH", tenantId: tenant.id, deferPipelines: true, metadata: { hostName: "TEST-MANUAL-01" } });
    const action = await recordResponseAction({ caseId: kase.id, actionType: "ISOLATE_HOST", target: "TEST-MANUAL-01", source: "analyst", status: "PENDING_APPROVAL" });
    const done = await performResponseAction(action.id, { id: adminId, name: "Test Admin" });
    expect(done.status).toBe("MANUAL_REQUIRED");
    expect(await db.endpoint.count({ where: { hostname: "TEST-MANUAL-01", isolated: true } })).toBe(0);
    expect((await db.case.findUniqueOrThrow({ where: { id: kase.id } })).status).not.toBe("CONTAINED");

    await expect(completeManualAction(action.id, { id: adminId, name: "Test Admin" }, "")).rejects.toThrow();
    const confirmed = await completeManualAction(action.id, { id: adminId, name: "Test Admin" }, "Isolated in the EDR console");
    expect(confirmed.status).toBe("EXECUTED");
    expect(await db.endpoint.count({ where: { hostname: "TEST-MANUAL-01", isolated: true } })).toBe(1);
    expect((await db.case.findUniqueOrThrow({ where: { id: kase.id } })).status).toBe("CONTAINED");
  });

  it("dispatches signed requests to the client's response connector", async () => {
    const tenant = await db.tenant.create({ data: { name: "Test · Connector", slug: "test-connector" } });
    await onboardIntegration({ tenantId: tenant.id, vendor: "response_webhook", config: { responseWebhookUrl: `${stubUrl}/actions` }, secrets: { webhookSecret: "test-secret" } }, adminId);
    const kase = await createCase({ sourceType: "SIEM_ALERT", title: "Connector containment", severity: "HIGH", tenantId: tenant.id, deferPipelines: true });
    const action = await recordResponseAction({ caseId: kase.id, actionType: "ISOLATE_HOST", target: "TEST-CONN-01", source: "analyst", status: "PENDING_APPROVAL" });
    const before = received.length;
    const done = await performResponseAction(action.id, { id: adminId, name: "Test Admin" });
    expect(done.status).toBe("EXECUTED");
    const req = received.slice(before).find((r) => r.path === "/actions")!;
    expect(JSON.parse(req.body)).toMatchObject({ action: "ISOLATE_HOST", target: "TEST-CONN-01", case: { id: kase.id } });
    expect(req.headers["x-helios-signature"]).toBe(signPayload("test-secret", String(req.headers["x-helios-timestamp"]), req.body));
    expect(await db.endpoint.count({ where: { tenantId: tenant.id, hostname: "TEST-CONN-01", isolated: true } })).toBe(1);
  });

  it("applies the client's signed rulebook to AI, analysts and approvals", async () => {
    const tenant = await db.tenant.create({ data: { name: "Test · Rulebook", slug: "test-rulebook", aiAutonomyCap: "AUTO_CONTAIN" } });
    const author = { id: adminId, name: "Test Admin" };
    const second = await db.user.create({ data: { email: "responder@test.local", name: "Second Responder", role: "INCIDENT_RESPONDER" } });
    await db.endpoint.create({ data: { tenantId: tenant.id, hostname: "TEST-DC-01", assetClass: "server", assetType: "domain_controller", criticality: "critical" } });

    // Saved, then signed on the client's behalf: only then does it apply.
    const body = {
      assets: { neverIsolate: [{ kind: "assetType", value: "domain_controller", note: "Domain controllers" }] },
      identities: { breakGlass: ["break-glass*"] },
      actions: { BLOCK_IP: { mode: "auto", autoFrom: "HIGH" } },
      blastRadius: { twoPerson: ["DISABLE_USER"] },
      approvers: { chain: [{ name: "Client CISO", contact: "ciso@test.local", channel: "phone", timeoutMinutes: 10 }], onTimeout: "suggest" },
    };
    await saveDraft(tenant.id, { body, reason: "Onboarding" }, author);
    expect(await rulebookVerdict({ tenantId: tenant.id, actionType: "ISOLATE_HOST", target: "TEST-DC-01", severity: "HIGH" })).toBeNull();
    await expect(signRulebook(tenant.id, { ...author, isClient: false }, "short")).rejects.toThrow();
    const v1 = await signRulebook(tenant.id, { ...author, isClient: false }, "Client CISO approved by email on 25 Oct");
    expect(v1).toMatchObject({ status: "ACTIVE", version: 1 });
    expect(await db.auditLog.count({ where: { action: "rulebook.activated" } })).toBe(1);

    const verdict = await rulebookVerdict({ tenantId: tenant.id, actionType: "ISOLATE_HOST", target: "TEST-DC-01", severity: "HIGH", fresh: true });
    expect(verdict?.hits.find((h) => h.outcome === "BLOCKED")).toMatchObject({ rule: "assets.neverIsolate[0]", hard: true });

    // An analyst can't isolate a never-isolate asset either.
    const kase = await createCase({ sourceType: "SIEM_ALERT", title: "Rulebook case", severity: "HIGH", tenantId: tenant.id, deferPipelines: true, metadata: { hostName: "TEST-DC-01" } });
    const blocked = await requestAnalystAction({ caseId: kase.id, actionType: "ISOLATE_HOST", target: "TEST-DC-01", actor: author, canApprove: true });
    expect(blocked).toMatchObject({ status: "BLOCKED", policyVersion: 1 });
    expect(await db.endpoint.count({ where: { hostname: "TEST-DC-01", isolated: true } })).toBe(0);
    const glass = await requestAnalystAction({ caseId: kase.id, actionType: "DISABLE_USER", target: "CORP\\break-glass-1", actor: author, canApprove: true });
    expect(glass.status).toBe("BLOCKED");

    // Two people for disabling an account: the requester's approval is one.
    const disable = await requestAnalystAction({ caseId: kase.id, actionType: "DISABLE_USER", target: "jdoe", actor: author, canApprove: true });
    expect(disable).toMatchObject({ status: "PENDING_APPROVAL", requiredApprovals: 2 });
    await expect(decideResponseAction(disable.id, "approved", author)).rejects.toThrow(/second person/);
    const done = await decideResponseAction(disable.id, "approved", { id: second.id, name: "Second Responder" });
    expect(done.status).toBe("MANUAL_REQUIRED");

    // A pending AI proposal walks the approver chain, then times out to a suggestion.
    const pending = await recordResponseAction({ caseId: kase.id, actionType: "BLOCK_IP", target: "203.0.113.50", source: "ai", status: "PENDING_APPROVAL" });
    const created = (await db.responseAction.findUniqueOrThrow({ where: { id: pending.id } })).createdAt;
    await escalatePendingApprovals(new Date(created.getTime() + 60_000));
    expect((await db.responseAction.findUniqueOrThrow({ where: { id: pending.id } })).escalation).toMatchObject({ step: 0 });
    await escalatePendingApprovals(new Date(created.getTime() + 11 * 60_000));
    const timedOut = await db.responseAction.findUniqueOrThrow({ where: { id: pending.id } });
    expect(timedOut.status).toBe("SUGGESTED");
    expect(timedOut.policyReason).toContain("downgraded to a suggestion");

    // Allowlisted entities don't open cases.
    await addAllowlistEntry(tenant.id, { kind: "ip", value: "10.9.9.9", reason: "Vulnerability scanner", owner: "Client IT", expiresAt: null }, author);
    const scan = (ip: string) => Array.from({ length: 15 }, (_, i) => ({ source: "network" as const, data: { timestamp: new Date(Date.now() - i * 1000).toISOString(), src_ip: ip, dst_ip: "10.0.0.5", dst_port: 1000 + i } }));
    const control = await ingestTelemetry(scan("10.9.9.8"), { tenantId: tenant.id });
    expect(control.casesCreated).toBeGreaterThan(0);
    const allowed = await ingestTelemetry(scan("10.9.9.9"), { tenantId: tenant.id });
    expect(allowed).toMatchObject({ casesCreated: 0, casesUpdated: 0 });
    expect(allowed.allowlisted).toBeGreaterThan(0);
  });

  it("chooses each client's AI model by its rules, key, evaluation and budget", async () => {
    const tenant = await db.tenant.create({ data: { name: "Test · AI choice", slug: "test-ai-choice" } });
    const author = { id: adminId, name: "Test Admin" };
    const cloud = await db.aiProvider.create({ data: { name: "Test cloud", kind: "anthropic", model: "claude-sonnet-5-5", isDefault: true, region: "us" } });
    const local = await db.aiProvider.create({ data: { name: "Test local", kind: "openai_compatible", baseUrl: "http://127.0.0.1:9/v1", model: "llama-test", isLocal: true } });
    const profile = await loadProfile("triage");

    // No rulebook: the platform default.
    expect((await resolveForClient("triage", profile, { tenantId: tenant.id })).resolution).toMatchObject({ source: "platform", providerId: cloud.id, redacted: false });

    // On-premises only: the cloud default is skipped, the local server runs it.
    await saveDraft(tenant.id, { body: { dataHandling: { residency: "onprem", redactPii: true } }, reason: "Residency" }, author);
    await signRulebook(tenant.id, { ...author, isClient: false }, "Client DPO approved by email");
    await db.tenantAiPolicy.create({ data: { tenantId: tenant.id, defaults: { triage: local.id } } });
    const onprem = await resolveForClient("triage", profile, { tenantId: tenant.id });
    expect(onprem.resolution).toMatchObject({ source: "client", providerId: local.id, isLocal: true, redacted: false });
    // A client-picked model that hasn't passed evaluation only suggests.
    expect(onprem.autonomyCap).toBe("SUGGEST");
    await db.modelCapability.create({ data: { model: "llama-test", agentKey: "triage", score: 0.93, passed: true, cases: 60 } });
    expect((await resolveForClient("triage", profile, { tenantId: tenant.id })).autonomyCap).toBeNull();

    // The client's own key, region-locked; masked for the cloud; never used for others.
    await saveDraft(tenant.id, { body: { dataHandling: { residency: "region", regions: ["india"], redactPii: true } }, reason: "Region" }, author);
    await signRulebook(tenant.id, { ...author, isClient: false }, "Client DPO approved by email");
    const own = await db.aiProvider.create({ data: { name: "Test · AI choice · Own Claude", kind: "anthropic", model: "claude-haiku-5-5", region: "india", tenantId: tenant.id } });
    await db.tenantAiPolicy.update({ where: { tenantId: tenant.id }, data: { defaults: { triage: own.id } } });
    const byo = await resolveForClient("triage", profile, { tenantId: tenant.id });
    expect(byo.resolution).toMatchObject({ source: "client", providerId: own.id, clientKey: true, redacted: true });
    const other = await db.tenant.create({ data: { name: "Test · Other", slug: "test-other" } });
    await db.tenantAiPolicy.create({ data: { tenantId: other.id, defaults: { triage: own.id } } });
    expect((await resolveForClient("triage", profile, { tenantId: other.id })).resolution).toMatchObject({ providerId: cloud.id });

    // Over budget: low-severity work moves to the built-in engine; client-key runs aren't counted.
    await db.tenantAiPolicy.update({ where: { tenantId: tenant.id }, data: { defaults: {}, monthlyBudgetUsd: 0.01 } });
    await saveDraft(tenant.id, { body: {}, reason: "Any provider" }, author);
    await signRulebook(tenant.id, { ...author, isClient: false }, "Client DPO approved by email");
    await db.aiModelPrice.upsert({ where: { model: "claude-sonnet-5-5" }, update: {}, create: { model: "claude-sonnet-5-5", provider: "anthropic", inputPer: 3, outputPer: 15, source: "test" } });
    await db.aiRun.create({ data: { tenantId: tenant.id, agentKey: "triage", trigger: "auto", engine: "Test cloud", model: "claude-sonnet-5-5", status: "succeeded", inputTokens: 100_000, outputTokens: 10_000 } });
    expect((await resolveForClient("triage", profile, { tenantId: tenant.id, severity: "LOW" })).resolution.source).toBe("builtin");
    expect((await resolveForClient("triage", profile, { tenantId: tenant.id, severity: "CRITICAL" })).resolution.source).toBe("platform");
    expect((await db.tenantAiPolicy.findUniqueOrThrow({ where: { tenantId: tenant.id } })).budgetReachedMonth).not.toBeNull();
    await db.aiProvider.deleteMany({ where: { id: { in: [cloud.id, local.id] } } });
  });

  it("imports a threat feed, matches it in detection, and drops delisted entries", async () => {
    const feed = await db.threatFeed.create({ data: { name: "Test feed", url: `${stubUrl}/feed.txt`, indicatorType: "IP", maliciousScore: 0.95, enabled: true } });
    feedBody = "# test feed\n198.51.100.77\n198.51.100.78\n10.0.0.1\nnot-an-ip\n";
    expect((await importFeed(feed.id)).lastCount).toBe(2);
    const listed = await db.threatIndicator.findUniqueOrThrow({ where: { type_value: { type: "IP", value: "198.51.100.77" } } });
    expect(listed).toMatchObject({ maliciousScore: 0.95, sources: ["feed:Test feed"] });

    const summary = await ingestTelemetry([{ source: "network", data: { source_ip: "10.1.1.5", dest_ip: "198.51.100.77", port: 443, hostname: "TEST-NET-01" } }], { actorId: adminId });
    expect(summary.newDetections).toBeGreaterThan(0);
    expect(await db.detection.count({ where: { source: "THREAT_INTEL_MATCH" } })).toBeGreaterThan(0);

    feedBody = "198.51.100.78\n";
    await importFeed(feed.id);
    const delisted = await db.threatIndicator.findUniqueOrThrow({ where: { type_value: { type: "IP", value: "198.51.100.77" } } });
    expect(delisted.maliciousScore).toBeNull();
    expect(delisted.sources).toEqual([]);
  });

  it("turns the database into a test environment, keeping its records as test data", async () => {
    const orphan = await createCase({ sourceType: "SIEM_ALERT", title: "Earlier sample alert", severity: "LOW", deferPipelines: true });
    const real = await db.tenant.create({ data: { name: "Adopted client", slug: "adopted-client" } });
    await adoptAsTestEnvironment(db);
    const moved = await db.case.findUniqueOrThrow({ where: { id: orphan.id }, include: { tenant: true } });
    expect(moved.tenant).toMatchObject({ slug: "test-earlier-data", isTest: true });
    expect(await db.case.count({ where: { tenantId: null } })).toBe(0);
    expect(await db.securityEvent.count({ where: { tenantId: null } })).toBe(0);
    expect((await db.tenant.findUniqueOrThrow({ where: { id: real.id } })).isTest).toBe(true);
    expect(await getSetting("platform.environment")).toBe("test");
    expect(await db.user.findUnique({ where: { email: "admin@helios.test" } })).toMatchObject({ role: "ADMIN" });
    expect(await db.auditLog.findFirst({ where: { action: "platform.environment_changed" } })).not.toBeNull();
  });

  it("stores provider keys sealed, preferring them over the environment", async () => {
    process.env.VIRUSTOTAL_API_KEY = "env-vt-key-0000";
    await storePlatformSecret("virustotal", "stored-vt-key-1234", adminId);
    const row = await db.platformSetting.findUniqueOrThrow({ where: { key: "secret.virustotal" } });
    expect(JSON.stringify(row.value)).not.toContain("stored-vt-key");
    expect(await platformSecret("virustotal")).toBe("stored-vt-key-1234");
    expect((await platformSecretStatus()).virustotal).toEqual({ source: "stored", last4: "1234" });
    await storePlatformSecret("virustotal", null, adminId);
    expect(await platformSecret("virustotal")).toBe("env-vt-key-0000");
    expect((await platformSecretStatus()).virustotal).toEqual({ source: "environment" });
    delete process.env.VIRUSTOTAL_API_KEY;
  });

  it("serves the REST API with per-user tokens", async () => {
    const acme = await db.tenant.create({ data: { name: "API Acme", slug: "api-acme" } });
    const other = await db.tenant.create({ data: { name: "API Other", slug: "api-other" } });
    const analyst = await db.user.create({ data: { email: "api.analyst@test.local", name: "API Analyst", role: "ANALYST" } });
    const clientAdmin = await db.user.create({ data: { email: "api.client@acme.test", name: "API Client", role: "CLIENT_ADMIN", tenantId: acme.id } });
    const own = await createCase({ sourceType: "SIEM_ALERT", title: "API: acme alert", severity: "HIGH", tenantId: acme.id, deferPipelines: true });
    const foreign = await createCase({ sourceType: "SIEM_ALERT", title: "API: other alert", severity: "LOW", tenantId: other.id, deferPipelines: true });

    const asUser = (u: { id: string; role: UserRole; tenantId: string | null }) => ({ id: u.id, role: u.role, tenantId: u.tenantId, tenantName: null, domains: [], isClient: u.role === "CLIENT_ADMIN", name: null, email: null });
    const { token: readToken } = await issueApiToken(asUser(analyst), { name: "read", canWrite: false, expiresInDays: 30 });
    const { token: writeToken, record: writeRecord } = await issueApiToken(asUser(analyst), { name: "write", canWrite: true, expiresInDays: null });
    const { token: clientToken } = await issueApiToken(asUser(clientAdmin), { name: "portal", canWrite: true, expiresInDays: 90 });
    expect((await db.apiToken.findUniqueOrThrow({ where: { id: writeRecord.id } })).tokenHash).not.toContain(writeToken);

    const call = (token: string | null, path: string, init: RequestInit = {}) =>
      new Request(`http://helios.test${path}`, { ...init, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), "content-type": "application/json" } });
    const ctx = (id: string) => ({ params: Promise.resolve({ id }) }) as never;

    expect((await meRoute.GET(call(null, "/api/v1/me"))).status).toBe(401);
    expect((await meRoute.GET(call("hpat_forged", "/api/v1/me"))).status).toBe(401);
    const me = await (await meRoute.GET(call(readToken, "/api/v1/me"))).json();
    expect(me).toMatchObject({ user: { email: "api.analyst@test.local", role: "ANALYST" }, token: { canWrite: false } });

    const list = await (await casesRoute.GET(call(readToken, "/api/v1/cases?status=all&limit=200"))).json();
    expect(list.data.map((c: { id: string }) => c.id)).toEqual(expect.arrayContaining([own.id, foreign.id]));

    expect((await caseRoute.PATCH(call(readToken, `/api/v1/cases/${own.id}`, { method: "PATCH", body: JSON.stringify({ status: "TRIAGING" }) }), ctx(own.id))).status).toBe(403);
    const patched = await caseRoute.PATCH(call(writeToken, `/api/v1/cases/${own.id}`, { method: "PATCH", body: JSON.stringify({ status: "TRIAGING", note: "via API" }) }), ctx(own.id));
    expect(patched.status).toBe(200);
    expect((await patched.json()).status).toBe("TRIAGING");
    expect(await db.auditLog.findFirst({ where: { caseId: own.id, action: "case.status_changed", actorId: analyst.id } })).not.toBeNull();
    expect((await caseRoute.PATCH(call(writeToken, `/api/v1/cases/${own.id}`, { method: "PATCH", body: JSON.stringify({ bogus: 1 }) }), ctx(own.id))).status).toBe(400);

    // A client token sees its own estate only, and its comments are always client-visible.
    const clientList = await (await casesRoute.GET(call(clientToken, "/api/v1/cases?status=all"))).json();
    expect(clientList.data.map((c: { id: string }) => c.id)).toEqual([own.id]);
    expect((await caseRoute.GET(call(clientToken, `/api/v1/cases/${foreign.id}`), ctx(foreign.id))).status).toBe(404);
    const comment = await commentsRoute.POST(call(clientToken, `/api/v1/cases/${own.id}/comments`, { method: "POST", body: JSON.stringify({ body: "Is this expected?" }) }), ctx(own.id));
    expect(comment.status).toBe(201);
    expect((await comment.json()).internal).toBe(false);
    expect((await caseRoute.PATCH(call(clientToken, `/api/v1/cases/${own.id}`, { method: "PATCH", body: JSON.stringify({ status: "RESOLVED" }) }), ctx(own.id))).status).toBe(403);

    await revokeApiToken(asUser(analyst), writeRecord.id);
    expect((await meRoute.GET(call(writeToken, "/api/v1/me"))).status).toBe(401);
  });

  it("reviews a client's current setup and numbers quotes without collisions", async () => {
    invalidateCatalog();
    const plan = await db.servicePlan.create({ data: { key: "test-upgrades", name: "Test upgrades plan", coverage: "24x7", ackMinutes: {}, containMinutes: {}, features: {}, pricePerEndpoint: 9 } });
    const tenant = await db.tenant.create({ data: { name: "Test · Upgrades", slug: "test-upgrades", industry: "Hospital group", planId: plan.id, endpointsLicensed: 10, usersLicensed: 12 } });
    await db.integration.createMany({
      data: [
        { tenantId: tenant.id, vendor: "jamf_pro", category: "mdm", name: "Jamf" },
        { tenantId: tenant.id, vendor: "entra_p1", category: "identity", name: "Entra" },
      ],
    });
    await db.endpoint.createMany({
      data: [
        { tenantId: tenant.id, hostname: "up-ws-1", os: "Windows 11 Pro" },
        { tenantId: tenant.id, hostname: "up-ws-2", os: "Windows 11 Pro" },
        { tenantId: tenant.id, hostname: "up-mac-1", os: "macOS 15" },
        { tenantId: tenant.id, hostname: "up-srv-1", os: "Windows Server 2022" },
        { tenantId: tenant.id, hostname: "up-fw-1", os: "FortiOS 7.4", assetClass: "network", assetType: "firewall" },
        { tenantId: tenant.id, hostname: "up-pump-1", assetClass: "iot_ot", assetType: "medical" },
      ],
    });
    const ctx = await loadPricingContext();
    const stack = await clientStackConfig(tenant.id, ctx);
    expect(stack!.config.plan).toBe("test-upgrades");
    expect(stack!.config.tools).toMatchObject({ mdm: "byo", identity: "byo" });
    expect(stack!.config.existing).toMatchObject({ mdm: "jamf_pro", identity: "entra_p1" });
    // 4 inventoried, 10 licensed: the other 6 are of unknown OS.
    expect(stack!.config.profile.mix).toMatchObject({ windows: 2, macos: 1, windowsServer: 1, other: 6 });
    expect(stack!.config.profile.users).toBe(12);
    // Non-device assets feed the estate, not the endpoint mix.
    expect(stack!.config.profile.estate).toMatchObject({ networkDevices: 1, otDevices: 1 });
    expect(stack!.config.context.industry).toBe("healthcare");
    const mdm = reviewUpgrades(stack!.config, ctx).find((r) => r.category.key === "mdm")!;
    expect(mdm.baseline?.key).toBe("jamf_pro");
    expect(mdm.options.find((o) => o.tool.key === "intune_p1")!.fitGain).toBe(2);

    const year = new Date().getUTCFullYear();
    const totals = calculateQuote(stack!.config, ctx);
    const data = { clientName: tenant.name, tenantId: tenant.id, config: JSON.parse(JSON.stringify(stack!.config)), totals: JSON.parse(JSON.stringify(totals)) };
    const [a, b] = await Promise.all([createQuote(data), createQuote(data)]);
    expect(new Set([a.reference, b.reference]).size).toBe(2);
    await db.quote.delete({ where: { id: [a, b].sort((x, y) => x.reference.localeCompare(y.reference))[0].id } });
    const c = await createQuote(data);
    expect(c.reference).toBe(`Q-${year}-${String(Math.max(Number(a.reference.slice(-4)), Number(b.reference.slice(-4))) + 1).padStart(4, "0")}`);
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
