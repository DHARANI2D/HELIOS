// Ported from asip's enrichment/virustotal.py VirusTotalClient — same mock
// fallback behavior when no API key is configured (VT lookups for common
// test/malicious values return a "flagged" mock instead of a live call).

export interface VtResult {
  maliciousCount: number;
  suspiciousCount: number;
  totalScanners: number;
  reputationScore: string;
  isMalicious: boolean;
  details: string;
}

const VT_BASE_URL = "https://www.virustotal.com/api/v3";

function mockResult(value: string): VtResult {
  const isKnownBad =
    value.includes("185.220.101.5") ||
    value.includes("update-service.net") ||
    value.includes("sha256_abc");

  const maliciousCount = isKnownBad ? 14 : 0;
  return {
    maliciousCount,
    suspiciousCount: 0,
    totalScanners: 70,
    reputationScore: `${maliciousCount}/70`,
    isMalicious: isKnownBad,
    details: isKnownBad
      ? "Mock threat flag: this indicator matches known threat behaviors in test datasets."
      : "VirusTotal API key is not configured. Returning unverified mock status.",
  };
}

async function request(path: string): Promise<VtResult> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return mockResult(path);

  try {
    const res = await fetch(`${VT_BASE_URL}${path}`, {
      headers: { "x-apikey": apiKey },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) throw new Error(`VirusTotal responded ${res.status}`);

    const data = await res.json();
    const stats = data?.data?.attributes?.last_analysis_stats ?? {};
    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const total = Object.values(stats).reduce(
      (sum: number, v) => sum + (typeof v === "number" ? v : 0),
      0,
    );

    return {
      maliciousCount: malicious,
      suspiciousCount: suspicious,
      totalScanners: total,
      reputationScore: `${malicious}/${total}`,
      isMalicious: malicious > 3,
      details: `VirusTotal: ${malicious} engines flagged this indicator as malicious.`,
    };
  } catch (err) {
    return {
      maliciousCount: 0,
      suspiciousCount: 0,
      totalScanners: 0,
      reputationScore: "error",
      isMalicious: false,
      details: `VirusTotal query failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

export const virustotal = {
  enrichHash: (hash: string) => request(`/files/${hash}`),
  enrichIp: (ip: string) => request(`/ip_addresses/${ip}`),
  enrichDomain: (domain: string) => request(`/domains/${domain}`),
};
