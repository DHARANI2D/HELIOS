import type { PrismaClient, SecurityDomain, UserRole } from "@prisma/client";
import bcrypt from "bcryptjs";

// Demo workspace for evaluating HELIOS as an MSSP: three clients on different
// plans, one user per role, onboarded tools, an endpoint inventory, and live
// cases already triaged by the AI first responder (built-in engine unless an
// AI provider is configured). Idempotent: re-running skips what exists.

const CLIENTS = [
  { slug: "northwind-health", name: "Northwind Health", industry: "Healthcare", plan: "professional", endpointsLicensed: 250, usersLicensed: 220, aiAutonomyCap: "AUTO_CONTAIN", contactName: "Dana Whitfield", contactEmail: "it.admin@northwind.example" },
  { slug: "contoso-retail", name: "Contoso Retail", industry: "Retail", plan: "essentials", endpointsLicensed: 120, usersLicensed: 140, aiAutonomyCap: "CONTAIN_WITH_APPROVAL", contactName: "Sam Okafor", contactEmail: "it@contoso.example" },
  { slug: "fabrikam-finance", name: "Fabrikam Finance", industry: "Financial services", plan: "enterprise", endpointsLicensed: 800, usersLicensed: 760, aiAutonomyCap: "CONTAIN_WITH_APPROVAL", contactName: "Priya Raman", contactEmail: "security@fabrikam.example" },
] as const;

const STAFF: Array<{ email: string; name: string; role: UserRole; title: string; domains?: SecurityDomain[] }> = [
  { email: "soc.manager@helios.local", name: "Morgan Lee", role: "SOC_MANAGER", title: "SOC manager" },
  { email: "triage@helios.local", name: "Alex Kim", role: "TRIAGE_ANALYST", title: "Tier-1 analyst", domains: ["ENDPOINT", "IDENTITY", "NETWORK"] },
  { email: "analyst@helios.local", name: "Jordan Reyes", role: "ANALYST", title: "Tier-2 analyst" },
  { email: "email.analyst@helios.local", name: "Sam Patel", role: "ANALYST", title: "Email security analyst", domains: ["EMAIL"] },
  { email: "responder@helios.local", name: "Riley Chen", role: "INCIDENT_RESPONDER", title: "Incident response lead" },
  { email: "hunter@helios.local", name: "Casey Novak", role: "THREAT_HUNTER", title: "Threat hunter" },
  { email: "engineer@helios.local", name: "Taylor Brooks", role: "DETECTION_ENGINEER", title: "Detection engineer" },
  { email: "auditor@helios.local", name: "Quinn Harper", role: "AUDITOR", title: "Compliance auditor" },
  { email: "sales@helios.local", name: "Avery Diaz", role: "SALES", title: "Account manager" },
];

const CLIENT_USERS: Array<{ email: string; name: string; role: UserRole; tenant: string }> = [
  { email: "it.admin@northwind.example", name: "Dana Whitfield", role: "CLIENT_ADMIN", tenant: "northwind-health" },
  { email: "ciso@northwind.example", name: "Elliot Marsh", role: "CLIENT_VIEWER", tenant: "northwind-health" },
  { email: "it@contoso.example", name: "Sam Okafor", role: "CLIENT_ADMIN", tenant: "contoso-retail" },
  { email: "security@fabrikam.example", name: "Priya Raman", role: "CLIENT_ADMIN", tenant: "fabrikam-finance" },
];

const TOOLS: Record<string, string[]> = {
  "northwind-health": ["crowdstrike_falcon_enterprise", "entra_p1", "defender_o365_p1"],
  "contoso-retail": ["defender_business", "okta_workforce"],
  "fabrikam-finance": ["sentinelone_complete", "entra_p2", "wazuh"],
};

const INVENTORY: Record<string, string> = {
  "northwind-health": `hostname,os,ip,owner,criticality,controls
FIN-LAPTOP-07,Windows 11,10.20.4.17,j.alvarez,standard,edr=active;av=active;host_firewall=active;disk_encryption=active;patching=degraded;mdm=active
EHR-DB-01,Windows Server 2022,10.20.0.21,it-ops,critical,edr=active;av=active;host_firewall=active;patching=active;backup=active
NURSE-STATION-12,Windows 10,10.20.9.12,shared,high,edr=active;av=active;disk_encryption=missing;patching=degraded
MAC-ADMIN-02,macOS 15,10.20.6.40,d.whitfield,standard,edr=active;av=active;disk_encryption=active;mdm=active`,
  "contoso-retail": `hostname,os,ip,owner,criticality,controls
POS-STORE-104,Windows 10 IoT,10.40.1.104,store-104,high,av=active;host_firewall=active;patching=missing
HQ-LAPTOP-21,Windows 11,10.40.0.21,s.okafor,standard,edr=active;av=active;disk_encryption=active;patching=active
WEB-SHOP-01,Ubuntu 22.04,10.40.5.10,ecom,critical,edr=active;av=missing;host_firewall=active;patching=active;backup=degraded`,
  "fabrikam-finance": `hostname,os,ip,owner,criticality,controls
FILESRV-02,Windows Server 2019,10.20.1.5,svc_backup,critical,edr=active;av=active;backup=active;patching=degraded
TRADER-WS-33,Windows 11,10.30.3.33,m.chen,high,edr=active;av=active;disk_encryption=active;patching=active;dlp=active
WEB-PROD-03,Ubuntu 22.04,10.20.8.30,web_admin,critical,edr=active;vuln_scan=active;host_firewall=active;patching=active`,
};

export async function seedDemo(db: PrismaClient) {
  // First response runs explicitly at the end, awaited, rather than detached.
  process.env.HELIOS_AI_FIRST_RESPONSE = "off";
  const { onboardIntegration, ingestForIntegration } = await import("../src/lib/integrations/service");
  const { samplePayloadFor } = await import("../src/lib/integrations/samples");
  const { applyInventory, parseInventoryCsv } = await import("../src/lib/endpoints/service");
  const { runSimulation } = await import("../src/lib/siem/simulation");
  const { maybeRunFirstResponse } = await import("../src/lib/ai/first-response");
  const { db: appDb } = await import("../src/lib/db");

  const password = process.env.SEED_DEMO_PASSWORD ?? "helios-demo";
  const passwordHash = await bcrypt.hash(password, 10);
  const admin = await db.user.findFirstOrThrow({ where: { role: "ADMIN" }, orderBy: { createdAt: "asc" } });

  const tenants = new Map<string, string>();
  for (const c of CLIENTS) {
    const t = await db.tenant.upsert({ where: { slug: c.slug }, update: {}, create: { ...c, status: "ACTIVE" } });
    tenants.set(c.slug, t.id);
  }

  for (const u of STAFF) {
    await db.user.upsert({ where: { email: u.email }, update: {}, create: { email: u.email, name: u.name, role: u.role, title: u.title, domains: u.domains ?? [], passwordHash } });
  }
  for (const u of CLIENT_USERS) {
    await db.user.upsert({ where: { email: u.email }, update: {}, create: { email: u.email, name: u.name, role: u.role, tenantId: tenants.get(u.tenant)!, passwordHash } });
  }

  let cases = 0;
  for (const [slug, tools] of Object.entries(TOOLS)) {
    const tenantId = tenants.get(slug)!;
    if ((await db.case.count({ where: { tenantId } })) > 0) continue; // already populated
    await applyInventory(tenantId, parseInventoryCsv(INVENTORY[slug]), "Demo inventory");
    for (const vendor of tools) {
      const existing = await db.integration.findFirst({ where: { tenantId, vendor } });
      const integration = existing ?? (await onboardIntegration({ tenantId, vendor }, admin.id)).integration;
      const sample = samplePayloadFor(vendor);
      if (sample) {
        const result = await ingestForIntegration(integration, sample);
        cases += result.casesCreated;
      }
    }
  }
  const northwind = tenants.get("northwind-health")!;
  if ((await db.securityEvent.count({ where: { tenantId: northwind } })) < 10) {
    const sim = await runSimulation({ tactics: ["Credential Access", "Lateral Movement"] }, admin.id, northwind);
    cases += sim.summary.casesCreated;
  }

  // AI first response on everything new, one at a time.
  const pending = await db.case.findMany({ where: { aiStatus: null, status: { notIn: ["RESOLVED", "FALSE_POSITIVE"] } }, select: { id: true } });
  for (const { id } of pending) await maybeRunFirstResponse(id);

  await appDb.$disconnect();
  console.log(`Demo workspace: ${CLIENTS.length} clients, ${STAFF.length + CLIENT_USERS.length} users (password: ${password}), ${cases} new cases, ${pending.length} AI first responses`);
}
