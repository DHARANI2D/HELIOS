import { z } from "zod";

// Which notifications also go out by email, SMS or WhatsApp, per person.
// Notifications always land in the app; these channels are on top, opt-in,
// in groups people understand. Pure and client-safe.

export const ALERT_CHANNELS = { email: "Email", sms: "SMS", whatsapp: "WhatsApp" } as const;
export type AlertChannel = keyof typeof ALERT_CHANNELS;
export const CHANNEL_KEYS = Object.keys(ALERT_CHANNELS) as AlertChannel[];

export const ALERT_GROUPS = [
  { key: "approvals", label: "Approvals waiting for me", kinds: ["approval"] },
  { key: "regulatory", label: "Regulatory deadlines (CERT-In, DPDP)", kinds: ["compliance"] },
  { key: "incidents", label: "Incident updates, escalations and SLA breaches", kinds: ["shared", "escalated", "sla"] },
  { key: "mine", label: "Cases assigned to me, mentions and cases I watch", kinds: ["assigned", "mention", "watching"] },
  { key: "sources", label: "Log sources going quiet", kinds: ["ingest"] },
  { key: "digest", label: "The daily digest of what HELIOS did", kinds: ["digest"] },
] as const;
export type AlertGroup = (typeof ALERT_GROUPS)[number]["key"];

export const E164 = /^\+[1-9]\d{6,14}$/;

const prefsSchema = z.record(z.string(), z.array(z.enum(CHANNEL_KEYS as [AlertChannel, ...AlertChannel[]])));
export type AlertPrefs = z.infer<typeof prefsSchema>;

export function parsePrefs(value: unknown): AlertPrefs {
  const parsed = prefsSchema.safeParse(value ?? {});
  return parsed.success ? parsed.data : {};
}

export const channelsFor = (prefs: AlertPrefs, kind: string): AlertChannel[] => [...new Set(prefs[kind] ?? [])];

// Group choices → stored per kind.
export function prefsFromGroups(groups: Partial<Record<AlertGroup, AlertChannel[]>>): AlertPrefs {
  const out: AlertPrefs = {};
  for (const g of ALERT_GROUPS) {
    const channels = [...new Set(groups[g.key] ?? [])];
    if (channels.length) for (const k of g.kinds) out[k] = channels;
  }
  return out;
}

export function groupsFromPrefs(prefs: AlertPrefs): Record<AlertGroup, AlertChannel[]> {
  return Object.fromEntries(ALERT_GROUPS.map((g) => [g.key, channelsFor(prefs, g.kinds[0])])) as Record<AlertGroup, AlertChannel[]>;
}

// An SMS-sized line: title, detail, link.
export function smsText(subject: string, body: string | null | undefined, link: string | null) {
  const head = `HELIOS: ${subject}`;
  const tail = link ? ` ${link}` : "";
  const room = 320 - head.length - tail.length - 3;
  const detail = body && room > 20 ? ` — ${body.length > room ? `${body.slice(0, room - 1)}…` : body}` : "";
  return `${head}${detail}${tail}`;
}
