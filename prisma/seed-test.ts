import { randomBytes } from "node:crypto";
import type { Prisma, PrismaClient, SecurityDomain, UserRole } from "@prisma/client";
import bcrypt from "bcryptjs";

// TEST DATA for exercising the platform end to end — `npm run db:seed:test`.
// Everything it creates is labelled: names start with "Test ·", every email
// address is under the reserved .test domain (RFC 2606, so nothing can reach
// a real mailbox), plans and prices it fills in say they're test values.
// Alerts come from the synthetic vendor payloads and attack scenarios in
// src/lib/__tests__/fixtures, pushed through the real ingest pipeline.
// Refuses to run against production. Idempotent: re-running skips what exists.
//
// `npm run db:test-env` goes further and makes the whole database a test
// environment (adoptAsTestEnvironment below) before loading the test data.

const TEST_PLANS = [
  {
    key: "test-24x7",
    name: "Test · 24×7 plan",
    tagline: "Test plan from db:seed:test — replace with your own",
    coverage: "24x7",
    ackMinutes: { CRITICAL: 30, HIGH: 120, MEDIUM: 480, LOW: 1440 },
    containMinutes: { CRITICAL: 120, HIGH: 480 },
    irRetainerHours: 10,
    pricePerEndpoint: 10,
    costPerEndpoint: 5,
    onboardingMinimum: 1000,
    defaultAutonomyCap: "AUTO_CONTAIN",
    features: { monitoring: "24×7 analysts", aiFirstResponse: true, autoContainment: "Pre-approved actions", threatHunting: "Monthly", irRetainer: "10 h / year", reporting: "Weekly", clientPortal: true },
    sortOrder: 2,
  },
  {
    key: "test-business-hours",
    name: "Test · Business-hours plan",
    tagline: "Test plan from db:seed:test — replace with your own",
    coverage: "8x5",
    ackMinutes: { CRITICAL: 60, HIGH: 240, MEDIUM: 1440, LOW: 4320 },
    containMinutes: { CRITICAL: 240, HIGH: 1440 },
    irRetainerHours: 0,
    pricePerEndpoint: 6,
    costPerEndpoint: 3,
    onboardingMinimum: 500,
    defaultAutonomyCap: "CONTAIN_WITH_APPROVAL",
    features: { monitoring: "8×5 analysts", aiFirstResponse: true, autoContainment: "With client approval", reporting: "Monthly", clientPortal: true },
    sortOrder: 1,
  },
] as const;

// Test values for the price book, only where an item isn't set yet.
const TEST_PRICES: Record<string, { price: number; cost?: number }> = {
  "svc.server": { price: 8, cost: 4 },
  "svc.identity": { price: 1, cost: 0.5 },
  "svc.compliance": { price: 400, cost: 200 },
  "svc.dedicated": { price: 2500, cost: 1800 },
  "svc.support.premium": { price: 8 },
  "onb.endpoint": { price: 15, cost: 6 },
  "onb.tool": { price: 300, cost: 150 },
  "ps.ir.hour": { price: 200, cost: 100 },
  "ps.pentest": { price: 5000, cost: 3000 },
  "ps.training": { price: 1000, cost: 400 },
  "ai.cloud.platform": { price: 0.5, cost: 0.1 },
  "ai.cloud.markup": { price: 20 },
  "ai.local.workstation": { price: 4000, cost: 3500 },
  "ai.local.server": { price: 10000, cost: 9000 },
  "ai.local.cluster": { price: 30000, cost: 27000 },
  "ai.local.hosting": { price: 150, cost: 100 },
  "ai.local.setup": { price: 2000, cost: 1000 },
  "terms.annual": { price: 5 },
  "terms.3year": { price: 10 },
  "terms.amc": { price: 15 },
  "terms.resale": { price: 0.8 },
};

const CLIENTS = [
  { slug: "test-clinic", name: "Test · Clinic", industry: "Healthcare (test)", plan: "test-24x7", endpointsLicensed: 40, usersLicensed: 35, aiAutonomyCap: "AUTO_CONTAIN", domain: "clinic.helios.test" },
  { slug: "test-retail", name: "Test · Retail", industry: "Retail (test)", plan: "test-business-hours", endpointsLicensed: 25, usersLicensed: 30, aiAutonomyCap: "CONTAIN_WITH_APPROVAL", domain: "retail.helios.test" },
] as const;

const STAFF: Array<{ role: UserRole; title: string; domains?: SecurityDomain[] }> = [
  { role: "SOC_MANAGER", title: "SOC manager" },
  { role: "TRIAGE_ANALYST", title: "Tier-1 analyst", domains: ["ENDPOINT", "IDENTITY", "NETWORK"] },
  { role: "ANALYST", title: "Tier-2 analyst" },
  { role: "INCIDENT_RESPONDER", title: "Incident responder" },
  { role: "THREAT_HUNTER", title: "Threat hunter" },
  { role: "DETECTION_ENGINEER", title: "Detection engineer" },
  { role: "AUDITOR", title: "Auditor" },
  { role: "SALES", title: "Account manager" },
];

const CLIENT_ROLES: UserRole[] = ["CLIENT_ADMIN", "CLIENT_VIEWER"];

const TOOLS: Record<string, string[]> = {
  "test-clinic": ["crowdstrike_falcon_enterprise", "entra_p1", "defender_o365_p1"],
  "test-retail": ["defender_business", "okta_workforce"],
};

const INVENTORY = `hostname,os,ip,owner,criticality,controls
TEST-WS-01,Windows 11,10.99.0.11,test.user1,standard,edr=active;av=active;host_firewall=active;disk_encryption=active;patching=degraded
TEST-WS-02,macOS 15,10.99.0.12,test.user2,standard,edr=active;av=active;disk_encryption=missing
TEST-SRV-01,Windows Server 2022,10.99.0.21,test.ops,critical,edr=active;av=active;patching=active;backup=active`;

// The fixture payloads reference this address; mark it known-bad the way an
// imported feed would, so the intel-match detectors have something to match.
const TEST_INDICATORS = [{ type: "IP" as const, value: "185.220.101.34", score: 0.9 }];

// One password for every test account in a run: SEED_TEST_PASSWORD, or
// generated once and printed.
let generatedPassword: string | undefined;
const testPassword = () => process.env.SEED_TEST_PASSWORD ?? (generatedPassword ??= randomBytes(9).toString("base64url"));

const slug = (role: string) => role.toLowerCase().replaceAll("_", ".");
const label = (role: string) => role.charAt(0) + role.slice(1).toLowerCase().replaceAll("_", " ");

function refuseProduction() {
  if (process.env.NODE_ENV === "production" && process.env.HELIOS_ALLOW_TEST_SEED !== "1") {
    throw new Error("Refusing to load test data with NODE_ENV=production (set HELIOS_ALLOW_TEST_SEED=1 to override)");
  }
}

const EARLIER_DATA = { slug: "test-earlier-data", name: "Test · Earlier sample data" };

// Turns this database into a test environment: whatever it already holds is
// kept and used as test data. Every client becomes a test client, records
// that belong to no client (sample data from before HELIOS served several
// clients) move to a labelled test client, and every page shows a
// test-environment banner. Switch back under Settings.
export async function adoptAsTestEnvironment(db: PrismaClient) {
  refuseProduction();
  const { setSetting } = await import("../src/lib/settings");
  const { logAction } = await import("../src/lib/audit");
  const admin = await db.user.findFirstOrThrow({ where: { role: "ADMIN" }, orderBy: { createdAt: "asc" } });

  const orphans = { tenantId: null };
  const [cases, events, endpoints, agents] = await Promise.all([db.case.count({ where: orphans }), db.securityEvent.count({ where: orphans }), db.endpoint.count({ where: orphans }), db.agent.count({ where: orphans })]);
  if (cases + events + endpoints + agents > 0) {
    const t = await db.tenant.upsert({
      where: { slug: EARLIER_DATA.slug },
      update: { isTest: true },
      create: { ...EARLIER_DATA, industry: "Test data", status: "ACTIVE", isTest: true, notes: "Holds the records that belonged to no client when this database became a test environment (npm run db:test-env)." },
    });
    await db.case.updateMany({ where: orphans, data: { tenantId: t.id } });
    await db.securityEvent.updateMany({ where: orphans, data: { tenantId: t.id } });
    await db.endpoint.updateMany({ where: orphans, data: { tenantId: t.id } });
    await db.agent.updateMany({ where: orphans, data: { tenantId: t.id } });
  }
  const marked = await db.tenant.updateMany({ where: { isTest: false }, data: { isTest: true } });
  // A test platform admin, so the whole environment can be driven with test
  // accounts — only here, never by the plain test seed next to real clients.
  await db.user.upsert({ where: { email: "admin@helios.test" }, update: {}, create: { email: "admin@helios.test", name: "Test Platform admin", role: "ADMIN", title: "Platform admin (test account)", passwordHash: await bcrypt.hash(testPassword(), 10) } });
  await setSetting("platform.environment", "test", admin.id);
  await logAction({ actorId: admin.id, action: "platform.environment_changed", detail: { to: "test", via: "npm run db:test-env", adopted: { cases, events, endpoints, agents }, clientsMarkedTest: marked.count } });
  console.log(`\n=== TEST ENVIRONMENT ===\nAdopted ${cases} cases, ${events} events, ${endpoints} endpoints and ${agents} agents that belonged to no client into "${EARLIER_DATA.name}"; ${marked.count} existing clients marked as test.`);
  console.log(`Test platform admin: admin@helios.test (password below)`);
}

export async function seedTest(db: PrismaClient) {
  refuseProduction();
  // First response runs explicitly at the end, awaited, rather than detached.
  process.env.HELIOS_AI_FIRST_RESPONSE = "off";
  const { onboardIntegration, ingestForIntegration } = await import("../src/lib/integrations/service");
  const { getCatalogTool } = await import("../src/lib/integrations/tools");
  const { samplePayloadFor } = await import("../src/lib/__tests__/fixtures/vendor-payloads");
  const { applyInventory, parseInventoryCsv } = await import("../src/lib/endpoints/service");
  const { runSimulation } = await import("../src/lib/__tests__/fixtures/siem/simulation");
  const { buildScenarios } = await import("../src/lib/__tests__/fixtures/governance/scenarios");
  const { issueAgentIdentity } = await import("../src/lib/governance/agents");
  const { evaluateAgentAction } = await import("../src/lib/governance/runtime");
  const { maybeRunFirstResponse } = await import("../src/lib/ai/first-response");
  const { PRICE_ITEM_INDEX } = await import("../src/lib/pricing/items");
  const { db: appDb } = await import("../src/lib/db");

  const password = testPassword();
  const passwordHash = await bcrypt.hash(password, 10);
  const admin = await db.user.findFirstOrThrow({ where: { role: "ADMIN" }, orderBy: { createdAt: "asc" } });

  const plans = new Map<string, { id: string; defaultAutonomyCap: string }>();
  for (const p of TEST_PLANS) {
    const plan = await db.servicePlan.upsert({ where: { key: p.key }, update: {}, create: { ...p, features: p.features as Prisma.InputJsonValue } });
    plans.set(p.key, plan);
  }
  let pricesFilled = 0;
  for (const [key, v] of Object.entries(TEST_PRICES)) {
    const def = PRICE_ITEM_INDEX.get(key);
    if (!def || (await db.priceItem.findUnique({ where: { key } }))?.price != null) continue;
    await db.priceItem.upsert({
      where: { key },
      update: { price: v.price, cost: v.cost ?? null, note: "Test value from db:seed:test" },
      create: { key, group: def.group, label: def.label, unit: def.unit, price: v.price, cost: v.cost ?? null, note: "Test value from db:seed:test" },
    });
    pricesFilled++;
  }

  const tenants = new Map<string, string>();
  for (const c of CLIENTS) {
    const t = await db.tenant.upsert({
      where: { slug: c.slug },
      update: { isTest: true },
      create: { slug: c.slug, name: c.name, industry: c.industry, planId: plans.get(c.plan)!.id, endpointsLicensed: c.endpointsLicensed, usersLicensed: c.usersLicensed, aiAutonomyCap: c.aiAutonomyCap, status: "ACTIVE", contactName: "Test contact", contactEmail: `it@${c.domain}`, notes: "Test client created by npm run db:seed:test", isTest: true },
    });
    tenants.set(c.slug, t.id);
  }

  const accounts: string[] = [];
  for (const u of STAFF) {
    const email = `${slug(u.role)}@helios.test`;
    await db.user.upsert({ where: { email }, update: {}, create: { email, name: `Test ${label(u.role)}`, role: u.role, title: `${u.title} (test account)`, domains: u.domains ?? [], passwordHash } });
    accounts.push(email);
  }
  for (const c of CLIENTS) {
    for (const role of CLIENT_ROLES) {
      const email = `${slug(role)}@${c.domain}`;
      await db.user.upsert({ where: { email }, update: {}, create: { email, name: `Test ${label(role)} (${c.name.replace("Test · ", "")})`, role, tenantId: tenants.get(c.slug)!, passwordHash } });
      accounts.push(email);
    }
  }

  for (const i of TEST_INDICATORS) {
    await db.threatIndicator.upsert({
      where: { type_value: { type: i.type, value: i.value } },
      update: {},
      create: { type: i.type, value: i.value, maliciousScore: i.score, sources: ["feed:Test fixtures"], providerData: { feeds: { "Test fixtures": { score: i.score, importedAt: new Date().toISOString(), description: "Test indicator from db:seed:test" } } }, expiresAt: new Date() },
    });
  }

  let cases = 0;
  for (const [tenantSlug, tools] of Object.entries(TOOLS)) {
    const tenantId = tenants.get(tenantSlug)!;
    if ((await db.case.count({ where: { tenantId } })) > 0) continue; // already populated
    await applyInventory(tenantId, parseInventoryCsv(INVENTORY), "Test inventory");
    for (const vendor of tools) {
      const tool = await getCatalogTool(vendor);
      if (!tool) continue;
      const existing = await db.integration.findFirst({ where: { tenantId, vendor } });
      const integration = existing ?? (await onboardIntegration({ tenantId, vendor, name: `Test · ${tool.vendor} ${tool.name}` }, admin.id)).integration;
      const payload = samplePayloadFor(tool);
      if (payload) cases += (await ingestForIntegration(integration, payload)).casesCreated;
    }
  }
  const clinic = tenants.get("test-clinic")!;
  if ((await db.securityEvent.count({ where: { tenantId: clinic, platform: { not: "helios-governance" } } })) < 10) {
    const sim = await runSimulation({ tactics: ["Credential Access", "Lateral Movement"] }, admin.id, clinic);
    cases += sim.summary.casesCreated;
  }

  // A governed AI agent, driven through the real governance gate.
  if (!(await db.agent.findUnique({ where: { name: "test-clinic-assistant" } }))) {
    const { agent } = await issueAgentIdentity("test-clinic-assistant", admin.id, clinic);
    const exfil = buildScenarios().find((s) => s.id === "data_exfiltration");
    for (const event of exfil?.events ?? []) {
      const fresh = await db.agent.findUniqueOrThrow({ where: { id: agent.id } });
      await evaluateAgentAction(fresh, event, "production");
    }
  }

  // Every test client's open cases, including any adopted by db:test-env.
  const pending = await db.case.findMany({ where: { tenant: { isTest: true }, aiStatus: null, status: { notIn: ["RESOLVED", "FALSE_POSITIVE"] } }, select: { id: true } });
  for (const { id } of pending) await maybeRunFirstResponse(id);

  await appDb.$disconnect();
  console.log("\n=== TEST DATA (do not use in production) ===");
  console.log(`${CLIENTS.length} test clients, ${TEST_PLANS.length} test plans, ${pricesFilled} test prices filled, ${cases} new cases, ${pending.length} AI first responses`);
  console.log(`${accounts.length} test accounts — password ${process.env.SEED_TEST_PASSWORD ? "from SEED_TEST_PASSWORD" : password}:`);
  for (const a of accounts) console.log(`  ${a}`);
}
