import type { IndicatorType } from "@prisma/client";

import { db } from "@/lib/db";
import { intelKey, type IntelSnapshot, type LocalVerdict } from "@/lib/threat-intel/local-intel";

// What the indicator store already knows about a batch of values: feed hits,
// provider reputations and blocks. Loaded once per batch so the synchronous
// detectors can match against real intelligence.

const MIN_SCORE = 0.1;

export async function loadIntelSnapshot(items: Array<{ type: IndicatorType; value: string | null | undefined }>): Promise<IntelSnapshot> {
  const byType = new Map<IndicatorType, Set<string>>();
  for (const { type, value } of items) {
    const v = value?.trim();
    if (!v) continue;
    if (!byType.has(type)) byType.set(type, new Set());
    byType.get(type)!.add(v);
    if (type !== "IP" && type !== "FILE_HASH") byType.get(type)!.add(v.toLowerCase());
  }
  if (byType.size === 0) return new Map();
  const rows = await db.threatIndicator.findMany({
    where: {
      OR: [...byType].map(([type, values]) => ({ type, value: { in: [...values] } })),
      AND: [{ OR: [{ maliciousScore: { gte: MIN_SCORE } }, { blockedAt: { not: null } }] }],
    },
    select: { type: true, value: true, maliciousScore: true, sources: true, blockedAt: true },
  });
  const snapshot = new Map<string, LocalVerdict>();
  for (const r of rows) {
    const reasons: string[] = [];
    const named = r.sources.filter((s) => s !== "local").map((s) => s.replace(/^feed:/, ""));
    if (r.maliciousScore != null && r.maliciousScore >= MIN_SCORE) reasons.push(`${named.length ? named.join(", ") : "indicator store"} reputation ${r.maliciousScore.toFixed(2)}`);
    if (r.blockedAt) reasons.push("on the HELIOS blocklist");
    // A block is an analyst's call that it's hostile.
    const score = Math.max(r.maliciousScore ?? 0, r.blockedAt ? 0.8 : 0);
    snapshot.set(intelKey(r.type, r.value), { score, reasons });
  }
  return snapshot;
}
