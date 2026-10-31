"use server";

import { revalidatePath } from "next/cache";
import type { IndicatorType } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { requirePermission } from "@/lib/session";
import { classifyIndicator } from "@/lib/threat-intel/indicators";
import { indicatorReasons, indicatorVerdict, lookupIndicator } from "@/lib/threat-intel/service";
import { configuredProviders } from "@/lib/threat-intel/providers";
import { importFeed } from "@/lib/threat-intel/feeds";
import { action } from "@/lib/action";
import { describeGeo, geoLookup, geoStatus } from "@/lib/geoip";

function serialize(result: Awaited<ReturnType<typeof lookupIndicator>>, providersConfigured: Awaited<ReturnType<typeof configuredProviders>>) {
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
    providersConfigured,
    errors: result.errors,
    // Where an IP is, from the server's GeoIP database (never sent anywhere).
    geo: indicator.type === "IP" ? describeGeo(geoLookup(indicator.value)) : null,
    geoAttribution: indicator.type === "IP" ? geoStatus().attribution : null,
  };
}

export type IndicatorLookup = ReturnType<typeof serialize>;

export const lookupAction = action(async function lookupAction(raw: string, force: boolean = false): Promise<IndicatorLookup> {
  const user = await requirePermission("intel.view");
  const ioc = classifyIndicator(raw);
  if (!ioc) throw new Error("Not a recognizable IP, domain, URL, file hash, or email address");
  const result = await lookupIndicator(ioc.type, ioc.value, { force });
  await logAction({ actorId: user.id, action: "intel.lookup", detail: { type: ioc.type, value: ioc.value, cached: result.cached } });
  revalidatePath("/threat-intel");
  return serialize(result, await configuredProviders());
});

export const recheckIndicatorAction = action(async function recheckIndicatorAction(indicatorId: string): Promise<IndicatorLookup> {
  const user = await requirePermission("intel.view");
  const indicator = await db.threatIndicator.findUniqueOrThrow({ where: { id: indicatorId } });
  const result = await lookupIndicator(indicator.type as IndicatorType, indicator.value, { force: true });
  await logAction({ actorId: user.id, action: "intel.lookup", detail: { type: indicator.type, value: indicator.value, forced: true } });
  revalidatePath("/threat-intel");
  const caseLinks = await db.caseIndicator.findMany({ where: { indicatorId }, select: { caseId: true } });
  for (const { caseId } of caseLinks) revalidatePath(`/cases/${caseId}`);
  return serialize(result, await configuredProviders());
});

export const setBlockedAction = action(async function setBlockedAction(indicatorId: string, blocked: boolean) {
  const user = await requirePermission("intel.manage");
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
});

export const setFeedEnabledAction = action(async function setFeedEnabledAction(feedId: string, enabled: boolean) {
  const user = await requirePermission("intel.manage");
  const feed = await db.threatFeed.update({ where: { id: feedId }, data: { enabled } });
  await logAction({ actorId: user.id, action: enabled ? "intel.feed_enabled" : "intel.feed_disabled", detail: { feed: feed.name } });
  revalidatePath("/threat-intel");
});

export const importFeedAction = action(async function importFeedAction(feedId: string) {
  const user = await requirePermission("intel.manage");
  const feed = await importFeed(feedId, user.id);
  revalidatePath("/threat-intel");
  return { name: feed.name, count: feed.lastCount ?? 0 };
});
