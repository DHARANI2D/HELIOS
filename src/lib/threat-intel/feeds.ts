import type { IndicatorType, Prisma, ThreatFeed } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { isPrivateIp } from "@/lib/threat-intel/indicators";
import { asProviderData, type StoredProviderData } from "@/lib/threat-intel/service";

// Imports public blocklist feeds (one indicator per line) into the shared
// indicator store, where every detector, investigation and email analysis
// matches against them. Each indicator remembers which feeds list it; one
// that drops off a feed loses that feed's score on the next import.

const MAX_BYTES = 25 * 1024 * 1024;
const MAX_ENTRIES = 100_000;
const CHUNK = 500;
const STALE_MS = 24 * 60 * 60 * 1000;

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function parseLine(type: IndicatorType, raw: string): string | null {
  const line = raw.split("#")[0].trim().split(/[\s,;]/)[0];
  if (!line) return null;
  switch (type) {
    case "IP":
      return IPV4.test(line) && !isPrivateIp(line) ? line : null;
    case "URL":
      try {
        const u = new URL(line);
        return u.protocol === "http:" || u.protocol === "https:" ? line : null;
      } catch {
        return null;
      }
    case "DOMAIN":
      return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(line) ? line.toLowerCase() : null;
    case "FILE_HASH":
      return /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(line) ? line.toLowerCase() : null;
    case "EMAIL_ADDRESS":
      return /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(line) ? line.toLowerCase() : null;
  }
}

function scoreOf(pd: StoredProviderData): { score: number | null; sources: string[] } {
  const scores: number[] = [];
  const sources: string[] = [];
  if (pd.local && pd.local.score > 0) {
    scores.push(pd.local.score);
    sources.push("local");
  }
  for (const [name, hit] of Object.entries(pd.feeds ?? {})) {
    scores.push(hit.score);
    sources.push(`feed:${name}`);
  }
  for (const [provider, value] of Object.entries(pd)) {
    if (provider === "local" || provider === "feeds" || !value || typeof value !== "object") continue;
    const s = (value as { score?: unknown }).score;
    if (typeof s === "number") {
      scores.push(s);
      sources.push(provider);
    }
  }
  return { score: scores.length ? Math.max(...scores) : null, sources };
}

async function fetchFeed(url: string) {
  const res = await fetch(url, { signal: AbortSignal.timeout(60_000), headers: { accept: "text/plain" } });
  if (!res.ok) throw new Error(`Feed returned HTTP ${res.status}`);
  const text = await res.text();
  if (text.length > MAX_BYTES) throw new Error("Feed larger than 25 MB");
  return text;
}

export async function importFeed(feedId: string, actorId?: string) {
  const feed = await db.threatFeed.findUniqueOrThrow({ where: { id: feedId } });
  try {
    const values = [...new Set((await fetchFeed(feed.url)).split(/\r?\n/).map((l) => parseLine(feed.indicatorType, l)).filter((v): v is string => !!v))].slice(0, MAX_ENTRIES);
    const listed = await applyFeed(feed, values);
    const updated = await db.threatFeed.update({ where: { id: feed.id }, data: { lastImportedAt: new Date(), lastCount: values.length, lastError: null } });
    await logAction({ actorId, action: "intel.feed_imported", detail: { feed: feed.name, entries: values.length, ...listed } });
    return updated;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await db.threatFeed.update({ where: { id: feed.id }, data: { lastError: message.slice(0, 500) } });
    throw new Error(`${feed.name}: ${message}`);
  }
}

async function applyFeed(feed: ThreatFeed, values: string[]) {
  const now = new Date().toISOString();
  const hit = { score: feed.maliciousScore, importedAt: now, description: feed.description ?? undefined };
  const current = new Set(values);
  let added = 0;
  let refreshed = 0;

  for (let i = 0; i < values.length; i += CHUNK) {
    const chunk = values.slice(i, i + CHUNK);
    const existing = await db.threatIndicator.findMany({ where: { type: feed.indicatorType, value: { in: chunk } }, select: { id: true, value: true, providerData: true } });
    const known = new Set(existing.map((e) => e.value));
    const fresh = chunk.filter((v) => !known.has(v));
    if (fresh.length) {
      const providerData: StoredProviderData = { feeds: { [feed.name]: hit } };
      const r = await db.threatIndicator.createMany({
        data: fresh.map((value) => ({ type: feed.indicatorType, value, maliciousScore: feed.maliciousScore, sources: [`feed:${feed.name}`], providerData: providerData as Prisma.InputJsonValue, expiresAt: new Date() })),
        skipDuplicates: true,
      });
      added += r.count;
    }
    await db.$transaction(
      existing.map((e) => {
        const pd = asProviderData(e.providerData);
        const next: StoredProviderData = { ...pd, feeds: { ...(pd.feeds ?? {}), [feed.name]: hit } };
        const { score, sources } = scoreOf(next);
        return db.threatIndicator.update({ where: { id: e.id }, data: { providerData: next as Prisma.InputJsonValue, maliciousScore: score, sources } });
      }),
    );
    refreshed += existing.length;
  }

  // Indicators this feed no longer lists lose its score.
  const source = `feed:${feed.name}`;
  let dropped = 0;
  let cursor: string | undefined;
  for (;;) {
    const page = await db.threatIndicator.findMany({
      where: { type: feed.indicatorType, sources: { has: source } },
      select: { id: true, value: true, providerData: true },
      orderBy: { id: "asc" },
      take: 2000,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });
    if (page.length === 0) break;
    cursor = page[page.length - 1].id;
    const stale = page.filter((r) => !current.has(r.value));
    if (stale.length) {
      await db.$transaction(
        stale.map((e) => {
          const pd = asProviderData(e.providerData);
          const feeds = { ...(pd.feeds ?? {}) };
          delete feeds[feed.name];
          const next: StoredProviderData = { ...pd, feeds };
          const { score, sources } = scoreOf(next);
          return db.threatIndicator.update({ where: { id: e.id }, data: { providerData: next as Prisma.InputJsonValue, maliciousScore: score, sources } });
        }),
      );
      dropped += stale.length;
    }
    if (page.length < 2000) break;
  }
  return { added, refreshed, dropped };
}

// Re-imports enabled feeds that are more than a day old. Called in the
// background when the Threat Intelligence page is opened.
export async function refreshStaleFeeds() {
  const feeds = await db.threatFeed.findMany({ where: { enabled: true, OR: [{ lastImportedAt: null }, { lastImportedAt: { lt: new Date(Date.now() - STALE_MS) } }] } });
  for (const f of feeds) await importFeed(f.id).catch(() => undefined);
  return feeds.length;
}
