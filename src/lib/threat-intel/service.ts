import type { IndicatorType, Prisma, ThreatIndicator } from "@prisma/client";

import { db } from "@/lib/db";
import { localVerdict, verdictForScore } from "@/lib/threat-intel/local-intel";
import {
  configuredProviders,
  isProviderError,
  queryProviders,
  type ProviderResult,
} from "@/lib/threat-intel/providers";

// The one shared IOC cache (ThreatIndicator) every module reads and writes —
// replaces signal-fusion's ThreatIntelCache, desas's per-run VT calls, and
// asip's enrichment manager.

const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24h, matching signal-fusion

interface StoredProviderData {
  local?: { score: number; reasons: string[] };
  [provider: string]: unknown;
}

function asProviderData(value: Prisma.JsonValue): StoredProviderData {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as StoredProviderData) : {};
}

// Records an indicator using built-in intel only. Never calls an external
// provider, so it's safe on hot paths (ingestion, email analysis). A freshly
// created row is marked already-expired so the first real lookup refreshes it.
export async function recordIndicator(type: IndicatorType, value: string): Promise<ThreatIndicator> {
  const local = localVerdict(type, value);
  const existing = await db.threatIndicator.findUnique({ where: { type_value: { type, value } } });
  if (existing) return existing;

  return db.threatIndicator.upsert({
    where: { type_value: { type, value } },
    update: {},
    create: {
      type,
      value,
      maliciousScore: local.score > 0 ? local.score : null,
      providerData: { local } as never,
      sources: local.score > 0 ? ["local"] : [],
      expiresAt: new Date(),
    },
  });
}

export interface LookupResult {
  indicator: ThreatIndicator;
  cached: boolean;
  providersConsulted: string[];
  errors: Array<{ provider: string; error: string }>;
}

export async function lookupIndicator(
  type: IndicatorType,
  value: string,
  options: { force?: boolean } = {},
): Promise<LookupResult> {
  const existing = await db.threatIndicator.findUnique({ where: { type_value: { type, value } } });
  if (existing && !options.force && existing.expiresAt > new Date()) {
    return { indicator: existing, cached: true, providersConsulted: existing.sources, errors: [] };
  }

  const local = localVerdict(type, value);
  const results = await queryProviders(type, value);
  const ok = results.filter((r): r is ProviderResult => !isProviderError(r));
  const errors = results.filter(isProviderError).map((e) => ({ provider: e.provider, error: e.error }));

  const providerData: StoredProviderData = { local };
  for (const r of results) providerData[r.provider] = isProviderError(r) ? { error: r.error } : r;

  const scores = [local.score, ...ok.map((r) => r.score)];
  const sources = [...(local.score > 0 ? ["local"] : []), ...ok.map((r) => r.provider)];
  const consulted = ok.length > 0;
  const maliciousScore = consulted || local.score > 0 ? Math.max(...scores) : null;

  const data = {
    maliciousScore,
    providerData: providerData as never,
    sources,
    lastCheckedAt: new Date(),
    // Only cache a real provider answer; a local-only result stays stale so
    // the next lookup tries again once keys are configured.
    expiresAt: consulted ? new Date(Date.now() + CACHE_TTL_MS) : new Date(),
  };

  const indicator = await db.threatIndicator.upsert({
    where: { type_value: { type, value } },
    update: data,
    create: { type, value, ...data },
  });

  return { indicator, cached: false, providersConsulted: ok.map((r) => r.provider), errors };
}

export function indicatorVerdict(indicator: Pick<ThreatIndicator, "maliciousScore" | "sources">) {
  const consulted = indicator.sources.some((s) => s !== "local");
  return verdictForScore(indicator.maliciousScore, consulted);
}

export function indicatorReasons(indicator: Pick<ThreatIndicator, "providerData">): string[] {
  const data = asProviderData(indicator.providerData);
  const reasons = [...(data.local?.reasons ?? [])];
  for (const [provider, value] of Object.entries(data)) {
    if (provider === "local" || !value || typeof value !== "object") continue;
    const v = value as { summary?: string; error?: string };
    if (v.summary) reasons.push(`${provider}: ${v.summary}`);
    if (v.error) reasons.push(`${provider}: lookup failed (${v.error})`);
  }
  return reasons;
}

// Provider enrichment for every indicator linked to a case. Bounded so a
// noisy case can't exhaust a free-tier API quota in one go.
export async function enrichCaseIndicators(caseId: string, limit = 15) {
  if (configuredProviders().length === 0) return 0;
  const links = await db.caseIndicator.findMany({
    where: { caseId, indicator: { expiresAt: { lte: new Date() } } },
    include: { indicator: true },
    take: limit,
  });
  for (const link of links) {
    await lookupIndicator(link.indicator.type, link.indicator.value);
  }
  return links.length;
}
