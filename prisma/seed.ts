import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

import { TACTICS, TECHNIQUES } from "../src/lib/mitre/catalog";
import { DEFAULT_PLAYBOOKS } from "../src/lib/playbooks/defaults";

const db = new PrismaClient();

async function seedAdmin() {
  const email = process.env.SEED_ADMIN_EMAIL ?? "admin@helios.local";
  const password = process.env.SEED_ADMIN_PASSWORD ?? "helios-admin";

  const passwordHash = await bcrypt.hash(password, 10);

  const user = await db.user.upsert({
    where: { email },
    update: {},
    create: {
      email,
      name: "HELIOS Admin",
      role: "ADMIN",
      passwordHash,
    },
  });

  console.log(`Seeded admin user: ${user.email} (password: ${password})`);
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

async function main() {
  await seedAdmin();
  await seedMitre();
  await seedPlaybooks();
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => db.$disconnect());
