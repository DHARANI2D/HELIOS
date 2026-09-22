// Ported from asip's enrichment/abuseipdb.py AbuseIPDBClient.

export interface AbuseIpResult {
  abuseScore: number;
  country: string;
  isp: string;
  isMalicious: boolean;
  details: string;
}

function mockResult(ip: string): AbuseIpResult {
  const isKnownBad = ip === "185.220.101.5"; // common Tor/C2 mock IP
  const abuseScore = isKnownBad ? 85 : 0;
  const country = isKnownBad ? "NL" : "US";
  const isp = isKnownBad ? "Tor Exit Node Provider" : "Google Cloud Platform";

  return {
    abuseScore,
    country,
    isp,
    isMalicious: isKnownBad,
    details: `Mock AbuseIPDB score: ${abuseScore}% (${country}, ${isp}) [API key missing]`,
  };
}

export async function enrichIp(ip: string): Promise<AbuseIpResult> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) return mockResult(ip);

  try {
    const url = new URL("https://api.abuseipdb.com/api/v2/check");
    url.searchParams.set("ipAddress", ip);
    url.searchParams.set("maxAgeInDays", "90");

    const res = await fetch(url, {
      headers: { Key: apiKey, Accept: "application/json" },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) throw new Error(`AbuseIPDB responded ${res.status}`);

    const { data } = await res.json();
    const abuseScore = data?.abuseConfidenceScore ?? 0;
    const country = data?.countryName ?? data?.countryCode ?? "Unknown";
    const isp = data?.isp ?? "Unknown";

    return {
      abuseScore,
      country,
      isp,
      isMalicious: abuseScore > 25,
      details: `AbuseIPDB score: ${abuseScore}% (${country}, ${isp})`,
    };
  } catch (err) {
    return {
      abuseScore: 0,
      country: "Unknown",
      isp: "Unknown",
      isMalicious: false,
      details: `AbuseIPDB query failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}
