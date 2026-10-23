import type { IndicatorType } from "@prisma/client";

// Provider clients ported from signal-fusion's threatIntelService (VirusTotal
// v3 + AbuseIPDB v2) and desas's body.check_url_intel. Each returns a
// normalized 0-1 score plus the raw-ish fields worth showing an analyst, or
// null when the provider has no opinion (not configured / unsupported type).

export interface ProviderResult {
  provider: "virustotal" | "abuseipdb";
  score: number;
  summary: string;
  data: Record<string, unknown>;
}

export interface ProviderError {
  provider: "virustotal" | "abuseipdb";
  error: string;
}

const TIMEOUT_MS = 10_000;

export function configuredProviders(): Array<ProviderResult["provider"]> {
  const out: Array<ProviderResult["provider"]> = [];
  if (process.env.VIRUSTOTAL_API_KEY) out.push("virustotal");
  if (process.env.ABUSEIPDB_API_KEY) out.push("abuseipdb");
  return out;
}

interface VtStats {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
}

// VT reports engine counts, not a probability. A handful of engines flagging
// an indicator is already a strong signal, so score saturates quickly rather
// than using the raw malicious/total ratio (which would rate 5/90 at 0.05).
export function scoreVirusTotalStats(stats: VtStats): number {
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  if (malicious === 0 && suspicious === 0) return 0;
  return Math.min(1, (malicious > 0 ? 0.4 + 0.06 * malicious : 0.2) + 0.03 * suspicious);
}

function vtPath(type: IndicatorType, value: string): string | null {
  switch (type) {
    case "IP":
      return `ip_addresses/${encodeURIComponent(value)}`;
    case "DOMAIN":
      return `domains/${encodeURIComponent(value)}`;
    case "FILE_HASH":
      return `files/${encodeURIComponent(value)}`;
    case "URL":
      return `urls/${Buffer.from(value).toString("base64url")}`;
    case "EMAIL_ADDRESS":
      return null;
  }
}

async function queryVirusTotal(type: IndicatorType, value: string): Promise<ProviderResult | ProviderError | null> {
  const key = process.env.VIRUSTOTAL_API_KEY;
  const path = vtPath(type, value);
  if (!key || !path) return null;

  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/${path}`, {
      headers: { "x-apikey": key },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (res.status === 404) {
      return { provider: "virustotal", score: 0, summary: "Not found in VirusTotal", data: { found: false } };
    }
    if (!res.ok) return { provider: "virustotal", error: `HTTP ${res.status}` };

    const body = (await res.json()) as { data?: { attributes?: Record<string, unknown> } };
    const attrs = body.data?.attributes ?? {};
    const stats = (attrs.last_analysis_stats ?? {}) as VtStats;
    const total = (stats.malicious ?? 0) + (stats.suspicious ?? 0) + (stats.harmless ?? 0) + (stats.undetected ?? 0);

    return {
      provider: "virustotal",
      score: scoreVirusTotalStats(stats),
      summary: `${stats.malicious ?? 0}/${total} engines flagged malicious`,
      data: {
        found: true,
        stats,
        reputation: attrs.reputation,
        country: attrs.country,
        asOwner: attrs.as_owner,
        registrar: attrs.registrar,
        categories: attrs.categories,
        typeDescription: attrs.type_description,
        names: Array.isArray(attrs.names) ? (attrs.names as string[]).slice(0, 5) : undefined,
        creationDate: attrs.creation_date,
      },
    };
  } catch (err) {
    return { provider: "virustotal", error: err instanceof Error ? err.message : String(err) };
  }
}

async function queryAbuseIpDb(type: IndicatorType, value: string): Promise<ProviderResult | ProviderError | null> {
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key || type !== "IP") return null;

  try {
    const url = new URL("https://api.abuseipdb.com/api/v2/check");
    url.searchParams.set("ipAddress", value);
    url.searchParams.set("maxAgeInDays", "90");
    const res = await fetch(url, {
      headers: { Key: key, Accept: "application/json" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return { provider: "abuseipdb", error: `HTTP ${res.status}` };

    const body = (await res.json()) as { data?: Record<string, unknown> };
    const data = body.data ?? {};
    const confidence = Number(data.abuseConfidenceScore ?? 0);
    return {
      provider: "abuseipdb",
      score: Math.max(0, Math.min(1, confidence / 100)),
      summary: `Abuse confidence ${confidence}% (${data.totalReports ?? 0} reports)`,
      data: {
        abuseConfidenceScore: confidence,
        totalReports: data.totalReports,
        usageType: data.usageType,
        isp: data.isp,
        domain: data.domain,
        countryCode: data.countryCode,
        isWhitelisted: data.isWhitelisted,
      },
    };
  } catch (err) {
    return { provider: "abuseipdb", error: err instanceof Error ? err.message : String(err) };
  }
}

export async function queryProviders(type: IndicatorType, value: string) {
  const results = await Promise.all([queryVirusTotal(type, value), queryAbuseIpDb(type, value)]);
  return results.filter((r): r is ProviderResult | ProviderError => r !== null);
}

export function isProviderError(r: ProviderResult | ProviderError): r is ProviderError {
  return "error" in r;
}
