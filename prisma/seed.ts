import { randomBytes } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

import { TACTICS, TECHNIQUES } from "../src/lib/mitre/catalog";
import { DEFAULT_PLAYBOOKS } from "../src/lib/playbooks/defaults";
import { AGENT_KEYS, AGENT_TYPES } from "../src/lib/ai/catalog";
import { CATALOG_TOOLS } from "./seed-data/tools";
import { BASE_CURRENCY, MODEL_PRICES, THREAT_FEEDS } from "./seed-data/reference";

const db = new PrismaClient();

// The first platform admin. The password comes from SEED_ADMIN_PASSWORD or
// is generated and printed once; an existing admin is never touched.
async function seedAdmin() {
  const email = (process.env.SEED_ADMIN_EMAIL ?? "admin@helios.local").toLowerCase();
  if (await db.user.findUnique({ where: { email } })) {
    console.log(`Admin ${email} already exists — unchanged`);
    return;
  }
  const password = process.env.SEED_ADMIN_PASSWORD ?? randomBytes(12).toString("base64url");
  if (password.length < 10) throw new Error("SEED_ADMIN_PASSWORD must be at least 10 characters");
  await db.user.create({ data: { email, name: process.env.SEED_ADMIN_NAME ?? "Platform admin", role: "ADMIN", passwordHash: await bcrypt.hash(password, 10) } });
  console.log(`Created admin ${email}${process.env.SEED_ADMIN_PASSWORD ? " (password from SEED_ADMIN_PASSWORD)" : ` with password ${password} — shown once, change it after signing in`}`);
}

// Real products and their published facts. Re-seeding refreshes the facts
// but never your own price (customPrice) or whether you offer the tool.
async function seedToolCatalog() {
  for (const t of CATALOG_TOOLS) {
    const facts = { name: t.name, vendor: t.vendor, category: t.category, description: t.description, controls: t.controls, actions: t.actions, ingest: t.ingest, platforms: t.platforms, deployment: t.deployment, offlineCapable: t.offlineCapable, priceUnit: t.priceUnit, listPrice: t.listPrice, priceSource: t.priceSource };
    await db.catalogTool.upsert({ where: { key: t.key }, update: facts, create: { key: t.key, ...facts } });
  }
  console.log(`Seeded tool catalog: ${CATALOG_TOOLS.length} products (${CATALOG_TOOLS.filter((t) => t.listPrice != null).length} with published prices)`);
}

// Published model prices, the base currency and the public threat feeds are
// created once; after that they're yours to edit.
async function seedReference() {
  for (const m of MODEL_PRICES) await db.aiModelPrice.upsert({ where: { model: m.model }, update: {}, create: m });
  await db.currency.upsert({ where: { code: BASE_CURRENCY.code }, update: { rate: 1 }, create: BASE_CURRENCY });
  for (const f of THREAT_FEEDS) await db.threatFeed.upsert({ where: { name: f.name }, update: {}, create: f });
  console.log(`Seeded ${MODEL_PRICES.length} model prices, base currency ${BASE_CURRENCY.code}, ${THREAT_FEEDS.length} threat feeds (disabled until you enable them)`);
}

// Idempotent: upserts so catalog edits (renamed techniques, new entries)
// reach existing databases on the next seed.
async function seedMitre() {
  for (const tactic of TACTICS) {
    await db.mitreTactic.upsert({
      where: { id: tactic.id },
      update: { name: tactic.name },
      create: { id: tactic.id, name: tactic.name },
    });
  }
  for (const t of TECHNIQUES) {
    const isSub = t.id.includes(".");
    const data = {
      name: t.name,
      tacticId: t.tactic,
      isSubtechnique: isSub,
      parentId: isSub ? t.id.split(".")[0] : null,
    };
    await db.mitreTechnique.upsert({ where: { id: t.id }, update: data, create: { id: t.id, ...data } });
  }
  console.log(`Seeded MITRE ATT&CK reference: ${TACTICS.length} tactics, ${TECHNIQUES.length} techniques`);
}

// Only creates playbooks that don't exist yet (matched by name), so analyst
// edits to the starter set are never overwritten.
async function seedPlaybooks() {
  let created = 0;
  for (const template of DEFAULT_PLAYBOOKS) {
    const existing = await db.playbook.findFirst({ where: { name: template.name } });
    if (existing) continue;
    await db.playbook.create({
      data: {
        name: template.name,
        description: template.description,
        triggerCondition: template.triggerCondition,
        autoExecute: template.autoExecute,
        requireApproval: template.requireApproval,
        priority: template.priority,
        actions: {
          create: template.actions.map((a, i) => ({
            name: a.name,
            actionType: a.actionType,
            parameters: a.parameters as never,
            order: i + 1,
          })),
        },
      },
    });
    created++;
  }
  console.log(`Seeded ${created} starter playbook(s)`);
}

// Creates missing agent profiles with their catalog defaults; never touches
// profiles an admin has already tuned.
async function seedAgentProfiles() {
  let created = 0;
  for (const key of AGENT_KEYS) {
    const type = AGENT_TYPES[key];
    const existing = await db.aiAgentProfile.findUnique({ where: { key } });
    if (existing) continue;
    await db.aiAgentProfile.create({
      data: {
        key,
        name: type.name,
        description: type.description,
        autonomy: type.defaultAutonomy,
        allowedActions: type.defaultActions,
        minConfidence: type.defaultMinConfidence,
      },
    });
    created++;
  }
  console.log(`Seeded ${created} AI agent profile(s)`);
}

async function main() {
  await seedAdmin();
  await seedMitre();
  await seedPlaybooks();
  await seedAgentProfiles();
  await seedToolCatalog();
  await seedReference();
  // `npm run db:seed:test` — clearly labelled test clients, plans, prices and
  // one account per role, for exercising the platform. Refuses production.
  if (process.argv.includes("--test")) {
    const { seedTest } = await import("./seed-test");
    await seedTest(db);
  }
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => db.$disconnect());
