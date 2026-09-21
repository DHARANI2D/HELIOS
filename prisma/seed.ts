import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const db = new PrismaClient();

async function main() {
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

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => db.$disconnect());
