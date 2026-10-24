import { db } from "@/lib/db";
import type { PriceBook } from "@/lib/pricing/catalog";

// Price-book overrides from the database, merged over the defaults by the
// calculator.
export async function loadPriceBook(): Promise<PriceBook> {
  const rows = await db.priceOverride.findMany();
  return Object.fromEntries(rows.map((r) => [r.itemKey, { price: r.unitPrice, cost: r.unitCost ?? undefined }]));
}
