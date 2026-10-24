import { getSetting, setSetting, type SettingKey } from "@/lib/settings";
import { seal, unseal } from "@/lib/secrets";

// Credentials for the platform's own services. A key saved under Settings is
// stored sealed (AES-256-GCM) and wins; otherwise the environment variable
// applies, so existing deployments keep working.

export const PLATFORM_SECRETS = {
  virustotal: { setting: "secret.virustotal", env: "VIRUSTOTAL_API_KEY", label: "VirusTotal API key", help: "IP, domain, URL and file-hash reputation in every module." },
  abuseipdb: { setting: "secret.abuseipdb", env: "ABUSEIPDB_API_KEY", label: "AbuseIPDB API key", help: "IP abuse reports for alerts, investigations and email senders." },
  mxtoolbox: { setting: "secret.mxtoolbox", env: "MXTOOLBOX_API_KEY", label: "MxToolbox API key", help: "Sender-domain diagnostics (MX, blacklist, SPF, DMARC, DKIM) in email forensics." },
  slackWebhook: { setting: "secret.slackWebhook", env: "SLACK_WEBHOOK_URL", label: "SOC Slack webhook", help: "The SOC's own channel for chat playbook steps when no Slack or Teams tool is onboarded." },
} as const satisfies Record<string, { setting: SettingKey; env: string; label: string; help: string }>;

export type PlatformSecret = keyof typeof PLATFORM_SECRETS;

// Lookups run on every enrichment; a short cache keeps them off the database.
const TTL_MS = 30_000;
const cache = new Map<PlatformSecret, { value: string | undefined; at: number }>();

async function stored(name: PlatformSecret): Promise<string | undefined> {
  try {
    const s = await getSetting(PLATFORM_SECRETS[name].setting);
    return s ? unseal(s.sealed) : undefined;
  } catch {
    return undefined; // no database (unit tests, build) or an unreadable seal
  }
}

export async function platformSecret(name: PlatformSecret): Promise<string | undefined> {
  const hit = cache.get(name);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.value;
  const value = (await stored(name)) || process.env[PLATFORM_SECRETS[name].env] || undefined;
  cache.set(name, { value, at: Date.now() });
  return value;
}

export interface SecretStatus {
  source: "stored" | "environment" | null;
  last4?: string;
}

export async function platformSecretStatus(): Promise<Record<PlatformSecret, SecretStatus>> {
  const names = Object.keys(PLATFORM_SECRETS) as PlatformSecret[];
  const entries = await Promise.all(
    names.map(async (name) => {
      const s = await getSetting(PLATFORM_SECRETS[name].setting);
      const status: SecretStatus = s ? { source: "stored", last4: s.last4 } : process.env[PLATFORM_SECRETS[name].env] ? { source: "environment" } : { source: null };
      return [name, status] as const;
    }),
  );
  return Object.fromEntries(entries) as Record<PlatformSecret, SecretStatus>;
}

// null clears the stored value (the environment variable applies again).
export async function storePlatformSecret(name: PlatformSecret, value: string | null, actorId: string) {
  const v = value?.trim();
  await setSetting(PLATFORM_SECRETS[name].setting, v ? { sealed: seal(v), last4: v.slice(-4) } : null, actorId);
  cache.delete(name);
}
