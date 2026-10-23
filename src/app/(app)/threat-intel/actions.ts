"use server";

import { revalidatePath } from "next/cache";
import type { IndicatorType } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { requireUser } from "@/lib/session";
import { classifyIndicator } from "@/lib/threat-intel/indicators";
import { indicatorReasons, indicatorVerdict, lookupIndicator } from "@/lib/threat-intel/service";
import { configuredProviders } from "@/lib/threat-intel/providers";

function serialize(result: Awaited<ReturnType<typeof lookupIndicator>>) {
  const { indicator } = result;
  return {
    id: indicator.id,
    type: indicator.type,
    value: indicator.value,
    maliciousScore: indicator.maliciousScore,
    verdict: indicatorVerdict(indicator),
    reasons: indicatorReasons(indicator),
    sources: indicator.sources,
    lastCheckedAt: indicator.lastCheckedAt.toISOString(),
    blockedAt: indicator.blockedAt?.toISOString() ?? null,
    cached: result.cached,
    providersConsulted: result.providersConsulted,
    providersConfigured: configuredProviders(),
    errors: result.errors,
  };
}

export type IndicatorLookup = ReturnType<typeof serialize>;

export async function lookupAction(raw: string, force = false): Promise<IndicatorLookup> {
  const user = await requireUser();
  const ioc = classifyIndicator(raw);
  if (!ioc) throw new Error("Not a recognizable IP, domain, URL, file hash, or email address");
  const result = await lookupIndicator(ioc.type, ioc.value, { force });
  await logAction({ actorId: user.id, action: "intel.lookup", detail: { type: ioc.type, value: ioc.value, cached: result.cached } });
  revalidatePath("/threat-intel");
  return serialize(result);
}

export async function recheckIndicatorAction(indicatorId: string): Promise<IndicatorLookup> {
  const user = await requireUser();
  const indicator = await db.threatIndicator.findUniqueOrThrow({ where: { id: indicatorId } });
  const result = await lookupIndicator(indicator.type as IndicatorType, indicator.value, { force: true });
  await logAction({ actorId: user.id, action: "intel.lookup", detail: { type: indicator.type, value: indicator.value, forced: true } });
  revalidatePath("/threat-intel");
  const caseLinks = await db.caseIndicator.findMany({ where: { indicatorId }, select: { caseId: true } });
  for (const { caseId } of caseLinks) revalidatePath(`/cases/${caseId}`);
  return serialize(result);
}

export async function setBlockedAction(indicatorId: string, blocked: boolean) {
  const user = await requireUser();
  const indicator = await db.threatIndicator.update({
    where: { id: indicatorId },
    data: { blockedAt: blocked ? new Date() : null },
  });
  await logAction({
    actorId: user.id,
    action: blocked ? "intel.blocked" : "intel.unblocked",
    detail: { type: indicator.type, value: indicator.value },
  });
  revalidatePath("/threat-intel");
}
