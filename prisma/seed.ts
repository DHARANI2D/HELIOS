import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const db = new PrismaClient();

async function main() {
  const ownerEmail = process.env.SEED_ADMIN_EMAIL ?? "admin@helios.local";
  const ownerPassword = process.env.SEED_ADMIN_PASSWORD ?? "helios-admin";
  const ownerPasswordHash = await bcrypt.hash(ownerPassword, 10);

  const owner = await db.user.upsert({
    where: { email: ownerEmail },
    update: { role: "PLATFORM_OWNER", organizationId: null },
    create: {
      email: ownerEmail,
      name: "HELIOS Platform Owner",
      role: "PLATFORM_OWNER",
      passwordHash: ownerPasswordHash,
    },
  });
  console.log(`Seeded platform owner: ${owner.email} (password: ${ownerPassword})`);

  // Demo tenant — created once, on the first seed run. Pre-tenancy demo
  // data (cases/agents/events/playbooks/audit entries created while this
  // app was still single-tenant) gets backfilled onto it below so the
  // existing demo content has a home to view it from as an org admin,
  // instead of silently becoming invisible platform-only rows.
  let demoOrg = await db.organization.findUnique({ where: { slug: "acme-demo" } });
  const isFirstRun = !demoOrg;

  demoOrg ??= await db.organization.create({
    data: {
      name: "Acme Corp (Demo Tenant)",
      slug: "acme-demo",
      status: "ACTIVE",
      aiTier: "PROFESSIONAL",
    },
  });
  console.log(`Seeded demo organization: ${demoOrg.name} (${demoOrg.slug})`);

  const orgAdminEmail = process.env.SEED_ORG_ADMIN_EMAIL ?? "admin@acme-demo.local";
  const orgAdminPassword = process.env.SEED_ORG_ADMIN_PASSWORD ?? "acme-admin";
  const orgAdminPasswordHash = await bcrypt.hash(orgAdminPassword, 10);

  const orgAdmin = await db.user.upsert({
    where: { email: orgAdminEmail },
    update: { role: "ORG_ADMIN", organizationId: demoOrg.id },
    create: {
      email: orgAdminEmail,
      name: "Acme Corp Admin",
      role: "ORG_ADMIN",
      organizationId: demoOrg.id,
      passwordHash: orgAdminPasswordHash,
    },
  });
  console.log(`Seeded demo org admin: ${orgAdmin.email} (password: ${orgAdminPassword})`);

  if (isFirstRun) {
    const [cases, agents, events, playbooks, auditLogs] = await Promise.all([
      db.case.updateMany({ where: { organizationId: null }, data: { organizationId: demoOrg.id } }),
      db.agent.updateMany({ where: { organizationId: null }, data: { organizationId: demoOrg.id } }),
      db.ingestedEvent.updateMany({ where: { organizationId: null }, data: { organizationId: demoOrg.id } }),
      db.playbook.updateMany({ where: { organizationId: null }, data: { organizationId: demoOrg.id } }),
      db.auditLog.updateMany({ where: { organizationId: null }, data: { organizationId: demoOrg.id } }),
    ]);
    console.log(
      `Backfilled pre-tenancy demo data onto ${demoOrg.slug}: ${cases.count} cases, ${agents.count} agents, ${events.count} events, ${playbooks.count} playbooks, ${auditLogs.count} audit entries.`,
    );
  }
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => db.$disconnect());
