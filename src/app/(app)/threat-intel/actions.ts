"use server";

import { revalidatePath } from "next/cache";

import { db } from "@/lib/db";
import { enrichIndicator } from "@/lib/threat-intel/service";
import type { IndicatorType } from "@prisma/client";

export async function lookupIndicatorAction(type: IndicatorType, value: string) {
  const result = await enrichIndicator(type, value);
  revalidatePath("/threat-intel");
  return result;
}

export async function listIndicatorsAction() {
  return db.threatIndicator.findMany({
    orderBy: { lastCheckedAt: "desc" },
    take: 100,
  });
}
