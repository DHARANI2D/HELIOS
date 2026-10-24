// Port of desas's analyzer/mxtoolbox.py: MxToolbox lookup API diagnostics
// for the sender's domain (MX, blacklist, SPF, DMARC, DNS, SMTP, and DKIM
// when the message carries a selector). Only runs with MXTOOLBOX_API_KEY.

export const MX_CHECKS = ["mx", "blacklist", "spf", "dmarc", "dns", "smtp", "dkim"] as const;
export type MxCheck = (typeof MX_CHECKS)[number];

export interface MxDetail {
  name: string;
  status: "PASS" | "FAIL" | "INFO";
  info: string;
}

export interface MxResult {
  checked: boolean;
  passed: boolean;
  details: MxDetail[];
}

export type MxDiagnostics = Record<MxCheck, MxResult>;

const BASE_URL = "https://api.mxtoolbox.com/api/v1/lookup";
const TIMEOUT_MS = 10_000;
const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i;

export function mxToolboxConfigured() {
  return !!process.env.MXTOOLBOX_API_KEY;
}

interface MxItem {
  Name?: string;
  Info?: string;
  Description?: string;
  Information?: string;
}

async function runCheck(command: MxCheck, argument: string, key: string): Promise<MxResult> {
  const result: MxResult = { checked: true, passed: false, details: [] };
  try {
    const res = await fetch(`${BASE_URL}/${command}/${encodeURIComponent(argument)}`, {
      headers: { Authorization: key, Accept: "application/json" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) {
      result.details.push({ name: "API error", status: "FAIL", info: `MxToolbox returned HTTP ${res.status}` });
      return result;
    }
    // MxToolbox sometimes omits the JSON content type; parse the text.
    const text = await res.text();
    let body: { Failed?: MxItem[]; Passed?: MxItem[]; Information?: MxItem[]; Warnings?: MxItem[] };
    try {
      body = JSON.parse(text);
    } catch {
      result.details.push({ name: "Decode error", status: "FAIL", info: `Expected JSON, got: ${text.slice(0, 120)}` });
      return result;
    }
    const describe = (i: MxItem) => i.Description || i.Info || i.Information || "";
    for (const item of body.Failed ?? []) result.details.push({ name: item.Name ?? "Error", status: "FAIL", info: describe(item) });
    for (const item of body.Passed ?? []) result.details.push({ name: item.Name ?? "Check", status: "PASS", info: describe(item) });
    for (const item of [...(body.Warnings ?? []), ...(body.Information ?? [])]) result.details.push({ name: item.Name ?? "Info", status: "INFO", info: describe(item) });
    result.passed = (body.Failed ?? []).length === 0;
  } catch (err) {
    result.details.push({ name: "Lookup error", status: "FAIL", info: err instanceof Error ? err.message : String(err) });
  }
  return result;
}

export async function queryMxToolbox(domain: string, dkimSelector?: string): Promise<MxDiagnostics | null> {
  const key = process.env.MXTOOLBOX_API_KEY;
  if (!key || !DOMAIN_RE.test(domain)) return null;

  const notChecked: MxResult = { checked: false, passed: true, details: [] };
  const entries = await Promise.all(
    MX_CHECKS.map(async (check) => {
      if (check === "dkim") {
        if (!dkimSelector || !/^[a-z0-9._-]+$/i.test(dkimSelector)) return [check, notChecked] as const;
        return [check, await runCheck("dkim", `${domain}:${dkimSelector}`, key)] as const;
      }
      return [check, await runCheck(check, domain, key)] as const;
    }),
  );
  return Object.fromEntries(entries) as MxDiagnostics;
}
