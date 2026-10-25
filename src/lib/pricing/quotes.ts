import { Prisma } from "@prisma/client";

import { db } from "@/lib/db";

// Quote references run Q-<year>-0001 upwards. The next number follows the
// highest one used this year, so a deleted quote doesn't make the sequence
// collide; two saves racing for one number are caught by the unique index
// and retried.

export async function nextQuoteReference(year = new Date().getUTCFullYear()) {
  const prefix = `Q-${year}-`;
  const last = await db.quote.findFirst({ where: { reference: { startsWith: prefix } }, orderBy: { reference: "desc" }, select: { reference: true } });
  const n = last ? Number.parseInt(last.reference.slice(prefix.length), 10) || 0 : 0;
  return `${prefix}${String(n + 1).padStart(4, "0")}`;
}

export async function createQuote(data: Omit<Prisma.QuoteUncheckedCreateInput, "reference">) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await db.quote.create({ data: { ...data, reference: await nextQuoteReference() } });
    } catch (err) {
      if (attempt < 3 && err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") continue;
      throw err;
    }
  }
}
