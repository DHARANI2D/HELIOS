import type { PrismaClient } from "@prisma/client";
import type { Net } from "../src/lib/testing/exposure";

// TEST DATA for the newer screens, added at the end of the test seed (and
// safe to run again on a database that already has test data: each part
// checks first and adds only what's missing):
//   - each test client's rulebook, in force after both approvals, and one
//     change waiting for them (Rule changes, Approvals);
//   - HELIOS's final analysis on each test client's worst open case;
//   - saved searches in Explore, for the SOC and for a client;
//   - two security tests for Test · Clinic: one run, with findings and an
//     imported scanner report, and one waiting for authorisation.
// The security test's probes are simulated here (reserved .example names
// and 203.0.113.x documentation addresses); nothing on a network is touched.

export interface DemoClient {
  slug: string;
  tenantId: string;
  domain: string;
  template: "healthcare" | "retail" | "general";
}

const CLOSED = ["RESOLVED", "FALSE_POSITIVE"] as const;

// A third test client holding sample cases from the project's own test
// fixtures, as in the test environment the guides were shot in: every
// attack scenario of the SIEM simulation, a log investigation (Sysmon), and
// email and file forensics (a phishing email, a macro document). Runs before
// the test seed's first responses, so its cases are triaged like the rest.
export async function seedSampleCases(db: PrismaClient, actorId: string) {
  const tenant = await db.tenant.upsert({
    where: { slug: "test-earlier-data" },
    update: { isTest: true },
    create: { slug: "test-earlier-data", name: "Test · Earlier sample data", industry: "Test data", status: "ACTIVE", isTest: true, contactName: "Test contact", contactEmail: "it@sample.helios.test", notes: "Sample cases from the test fixtures: the attack-scenario simulation, a log investigation and email and file forensics (npm run db:seed:test)." },
  });
  if (await db.case.count({ where: { tenantId: tenant.id } })) return null;
  const { runSimulation } = await import("../src/lib/__tests__/fixtures/siem/simulation");
  const { SAMPLE_INVESTIGATION } = await import("../src/lib/__tests__/fixtures/investigations");
  const { buildSampleEmail } = await import("../src/lib/__tests__/fixtures/forensics");
  const { DROPPER_MACRO } = await import("../src/lib/__tests__/fixtures/macros");
  const { buildMacroDocument } = await import("../src/lib/__tests__/fixtures/vba-builder");
  const { runInvestigationPipeline, startInvestigation } = await import("../src/lib/investigations/service");
  const { analyzeSubmission } = await import("../src/lib/forensics/service");

  const sim = await runSimulation({ count: 1000 }, actorId, tenant.id);
  const inv = await startInvestigation({ title: SAMPLE_INVESTIGATION.title, alertDetails: SAMPLE_INVESTIGATION.alertDetails, files: [], pastedLogs: SAMPLE_INVESTIGATION.logs, actorId, tenantId: tenant.id });
  await runInvestigationPipeline(inv.caseId);
  await analyzeSubmission({ ...buildSampleEmail(), detonate: false, actorId, tenantId: tenant.id });
  await analyzeSubmission({ filename: "invoice-macro.doc", bytes: buildMacroDocument(DROPPER_MACRO), detonate: false, actorId, tenantId: tenant.id });
  return `Test · Earlier sample data: ${sim.summary.casesCreated} cases from the attack scenarios, an investigation and two forensics cases`;
}

export async function seedFeatureDemos(db: PrismaClient, clients: DemoClient[]) {
  const { saveDraft, submitForSignature, signRulebook } = await import("../src/lib/rulebook/service");
  const { buildTemplate } = await import("../src/lib/rulebook/templates");
  const { analyseCase } = await import("../src/lib/ai/autopilot");
  const { authoriseTest, importResults, requestTest, runTest, verifyTest } = await import("../src/lib/testing/service");

  const actor = async (email: string) => {
    const u = await db.user.findUniqueOrThrow({ where: { email } });
    return { id: u.id, name: u.name ?? email, role: u.role, isClient: !!u.tenantId, tenantId: u.tenantId };
  };
  const manager = await actor("soc.manager@helios.test");
  const hunter = await actor("threat.hunter@helios.test");
  const analyst = await actor("analyst@helios.test");
  const done: string[] = [];

  // 1. Rulebooks in force, approved by the client's admin and a HELIOS approver.
  for (const c of clients) {
    if (await db.orgPolicy.count({ where: { tenantId: c.tenantId, status: "ACTIVE" } })) continue;
    const clientAdmin = await actor(`client.admin@${c.domain}`);
    await saveDraft(c.tenantId, { body: buildTemplate(c.template), reason: "Test rulebook from the test seed, from the industry template", template: c.template }, clientAdmin);
    await submitForSignature(c.tenantId, clientAdmin);
    await signRulebook(c.tenantId, clientAdmin, "Approved for the test client", "client");
    await signRulebook(c.tenantId, manager, "Approved for HELIOS (test data)", "helios");
    done.push(`rulebook in force for ${c.slug}`);
  }

  // 2. A rule change waiting for both approvals.
  const clinic = clients.find((c) => c.slug === "test-clinic");
  if (clinic && !(await db.ruleChange.count({ where: { tenantId: clinic.tenantId, status: "PENDING" } }))) {
    const active = await db.orgPolicy.findFirstOrThrow({ where: { tenantId: clinic.tenantId, status: "ACTIVE" } });
    const body = JSON.parse(JSON.stringify(active.body));
    body.actions = body.actions ?? {};
    body.actions.BLOCK_IP = { ...(body.actions.BLOCK_IP ?? {}), mode: "auto", autoFrom: "MEDIUM" };
    const clientAdmin = await actor(`client.admin@${clinic.domain}`);
    await saveDraft(clinic.tenantId, { body, reason: "Block known-bad IPs from medium severity: the clinic's firewall team asked for faster blocking" }, clientAdmin);
    await submitForSignature(clinic.tenantId, clientAdmin);
    done.push("a rule change waiting for approval (Test · Clinic)");
  }

  // 3. HELIOS's final analysis on each test client's worst open case.
  for (const c of clients) {
    if (await db.caseReport.count({ where: { tenantId: c.tenantId } })) continue;
    const kase = await db.case.findFirst({
      where: { tenantId: c.tenantId, aiStatus: "completed", status: { notIn: [...CLOSED] } },
      orderBy: [{ severity: "desc" }, { riskScore: "desc" }],
      select: { id: true },
    });
    if (!kase) continue;
    await db.case.update({ where: { id: kase.id }, data: { analysisStatus: "running", analysisUpdatedAt: new Date() } });
    await analyseCase(kase.id, { refresh: false });
    done.push(`final analysis for ${c.slug}`);
  }

  // 4. Saved searches in Explore.
  if (!(await db.savedSearch.count({ where: { owner: { email: { endsWith: ".test" } } } }))) {
    await db.savedSearch.create({ data: { name: "Failed sign-ins", query: "type:LOGIN_FAIL", range: "30d", ownerId: analyst.id, shared: true } });
    await db.savedSearch.create({ data: { name: "Encoded PowerShell", query: 'process:*powershell* cmd:"*-enc*"', range: "30d", ownerId: analyst.id, shared: true } });
    if (clinic) {
      const clientAdmin = await actor(`client.admin@${clinic.domain}`);
      await db.savedSearch.create({ data: { name: "Our failed sign-ins", query: "type:LOGIN_FAIL", range: "30d", tenantId: clinic.tenantId, ownerId: clientAdmin.id, shared: true } });
    }
    done.push("saved searches");
  }

  // 5. Security tests for Test · Clinic.
  if (clinic && !(await db.securityTest.count({ where: { tenantId: clinic.tenantId } }))) {
    const clientAdmin = await actor(`client.admin@${clinic.domain}`);
    const now = new Date();
    const t = await requestTest(
      {
        tenantId: clinic.tenantId,
        title: "External exposure check, Q4",
        targets: "clinic.example portal.clinic.example 203.0.113.60",
        checks: ["services", "tls", "web", "email"],
        rulesOfEngagement: "Test data: the probes in this report were simulated by the test seed.\nContact: the clinic's IT lead.\nOut of bounds: anything not listed here.\nAvoid: Monday mornings (patient intake).",
        windowStart: new Date(now.getTime() + 60_000),
        windowEnd: new Date(now.getTime() + 7 * 86_400_000),
      },
      hunter,
    );
    await db.securityTest.update({ where: { id: t.id }, data: { windowStart: new Date(now.getTime() - 2 * 3_600_000) } });
    // A simulated network: the DNS proof, a few open services, a certificate
    // close to expiry, missing web headers and a soft SPF record.
    const txt: Record<string, string[]> = { "clinic.example": [`helios-verify=${t.verifyToken}`, "v=spf1 include:_spf.mail.example ~all"] };
    const addrs: Record<string, string[]> = { "clinic.example": ["203.0.113.61"], "portal.clinic.example": ["203.0.113.60"] };
    const open: Record<string, number[]> = { "203.0.113.60": [443, 3389, 22], "203.0.113.61": [80, 443] };
    const net: Net = {
      txt: async (n: string) => (txt[n] ?? []).map((r) => [r]),
      addresses: async (n: string) => addrs[n] ?? [],
      connect: async (ip: string, port: number) => ({ open: !!open[ip]?.includes(port), banner: port === 22 ? "SSH-2.0-OpenSSH_7.4" : null }),
      tls: async (ip: string) => ({ subject: ip === "203.0.113.60" ? "portal.clinic.example" : "clinic.example", issuer: "Example Issuing CA", validTo: new Date(now.getTime() + (ip === "203.0.113.60" ? 9 : 120) * 86_400_000).toISOString(), names: [ip === "203.0.113.60" ? "portal.clinic.example" : "clinic.example"], selfSigned: false, authorized: true, authorizationError: null, protocol: "TLSv1.3" }),
      http: async (url: string) => ({ status: 200, headers: (url.startsWith("http://") ? {} : { server: "nginx/1.18.0", "x-content-type-options": "nosniff" }) as Record<string, string> }),
    };
    await verifyTest(t.id, clientAdmin, net);
    await authoriseTest(t.id, clientAdmin, { attest: true });
    await authoriseTest(t.id, manager, {});
    await db.securityTest.update({ where: { id: t.id }, data: { status: "running", startedAt: new Date() } });
    await runTest(t.id, net);
    await importResults(t.id, hunter, {
      name: "clinic-q4.nessus",
      text: `<NessusClientData_v2><Report><ReportHost name="203.0.113.60"><HostProperties><tag name="host-fqdn">portal.clinic.example</tag></HostProperties><ReportItem port="443" svc_name="www" severity="3" pluginID="157288" pluginName="nginx 1.18 &lt; 1.20.1 1-Byte Memory Overwrite"><synopsis>The web server is affected by a memory overwrite vulnerability.</synopsis><solution>Upgrade nginx to 1.20.1 or later.</solution><cve>CVE-2021-23017</cve></ReportItem></ReportHost><ReportHost name="198.51.100.80"><ReportItem port="22" severity="4" pluginID="1" pluginName="Out of scope host"><solution>-</solution></ReportItem></ReportHost></Report></NessusClientData_v2>`,
    });
    await requestTest(
      {
        tenantId: clinic.tenantId,
        title: "Patient portal web check",
        targets: "https://portal.clinic.example",
        checks: ["tls", "web"],
        rulesOfEngagement: "Test data.\nContact: the clinic's IT lead.\nOut of bounds: everything except the portal.",
        windowStart: new Date(now.getTime() + 3 * 86_400_000),
        windowEnd: new Date(now.getTime() + 5 * 86_400_000),
      },
      clientAdmin,
    );
    done.push("two security tests (Test · Clinic)");
  }
  return done;
}
