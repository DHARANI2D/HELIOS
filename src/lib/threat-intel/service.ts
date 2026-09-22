import { db } from "@/lib/db";
import { virustotal } from "@/lib/threat-intel/virustotal";
import { enrichIp as abuseipdbEnrichIp } from "@/lib/threat-intel/abuseipdb";
import type { IndicatorType, ThreatIndicator } from "@prisma/client";

// The one shared IOC enrichment entrypoint, replacing asip's
// EnrichmentManager, desas's separate VT/AbuseIPDB calls, and
// signal-fusion's threatIntelService — all three had their own client and
// their own ad hoc cache. This one has a single 24h-TTL cache
// (ThreatIndicator) backing every module.

const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

export interface EnrichmentSummary {
  maliciousScore: number; // 0-1
  isMalicious: boolean;
  summary: string;
}

async function enrichByType(
  type: IndicatorType,
  value: string,
): Promise<{ providerData: Record<string, unknown>; summary: EnrichmentSummary }> {
  switch (type) {
    case "IP": {
      const [vt, abuse] = await Promise.all([
        virustotal.enrichIp(value),
        abuseipdbEnrichIp(value),
      ]);
      const score = Math.max(
        vt.isMalicious ? Math.min(1, vt.maliciousCount / 20) : 0,
        abuse.abuseScore / 100,
      );
      return {
        providerData: { virustotal: vt, abuseipdb: abuse },
        summary: {
          maliciousScore: score,
          isMalicious: vt.isMalicious || abuse.isMalicious,
          summary: `VT ${vt.reputationScore} · AbuseIPDB ${abuse.abuseScore}% (${abuse.country})`,
        },
      };
    }
    case "DOMAIN":
    case "URL": {
      const vt = await virustotal.enrichDomain(value);
      return {
        providerData: { virustotal: vt },
        summary: {
          maliciousScore: vt.isMalicious ? Math.min(1, vt.maliciousCount / 20) : 0,
          isMalicious: vt.isMalicious,
          summary: vt.details,
        },
      };
    }
    case "FILE_HASH": {
      const vt = await virustotal.enrichHash(value);
      return {
        providerData: { virustotal: vt },
        summary: {
          maliciousScore: vt.isMalicious ? Math.min(1, vt.maliciousCount / 20) : 0,
          isMalicious: vt.isMalicious,
          summary: vt.details,
        },
      };
    }
    case "EMAIL_ADDRESS": {
      const domain = value.split("@")[1] ?? value;
      const vt = await virustotal.enrichDomain(domain);
      return {
        providerData: { virustotal: vt, derivedDomain: domain },
        summary: {
          maliciousScore: vt.isMalicious ? Math.min(1, vt.maliciousCount / 20) : 0,
          isMalicious: vt.isMalicious,
          summary: `Sender domain (${domain}): ${vt.details}`,
        },
      };
    }
  }
}

export async function enrichIndicator(
  type: IndicatorType,
  rawValue: string,
): Promise<ThreatIndicator> {
  const value = rawValue.trim().toLowerCase();

  const cached = await db.threatIndicator.findUnique({
    where: { type_value: { type, value } },
  });
  if (cached && cached.expiresAt > new Date()) {
    return cached;
  }

  const { providerData, summary } = await enrichByType(type, value);

  return db.threatIndicator.upsert({
    where: { type_value: { type, value } },
    create: {
      type,
      value,
      maliciousScore: summary.maliciousScore,
      providerData: providerData as never,
      expiresAt: new Date(Date.now() + CACHE_TTL_MS),
    },
    update: {
      maliciousScore: summary.maliciousScore,
      providerData: providerData as never,
      lastCheckedAt: new Date(),
      expiresAt: new Date(Date.now() + CACHE_TTL_MS),
    },
  });
}

export async function enrichMany(
  indicators: Array<{ type: IndicatorType; value: string }>,
): Promise<ThreatIndicator[]> {
  return Promise.all(indicators.map((i) => enrichIndicator(i.type, i.value)));
}
