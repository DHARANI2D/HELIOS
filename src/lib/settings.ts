import { cache } from "react";
import type { CaseSeverity } from "@prisma/client";
import { z } from "zod";

import { db } from "@/lib/db";

// Platform-wide switches, stored in platform_settings and edited from the AI
// Agents and Settings pages. Defaults apply until someone saves a value.

const text = (max: number) => z.string().trim().max(max);

// The MSSP's own details: printed on quotes and reports, shown to clients.
export const companySchema = z.object({
  name: text(120),
  legalName: text(160),
  address: text(400),
  email: z.string().trim().email().max(200).or(z.literal("")),
  phone: text(60),
  website: text(200),
  taxId: text(60),
  quoteTerms: text(4000),
  reportFooter: text(400),
});
export type CompanyProfile = z.infer<typeof companySchema>;
const NO_COMPANY: CompanyProfile = { name: "", legalName: "", address: "", email: "", phone: "", website: "", taxId: "", quoteTerms: "", reportFooter: "" };

export const thresholdsSchema = z
  .object({ malicious: z.number().int().min(2).max(500), suspicious: z.number().int().min(1).max(499) })
  .refine((t) => t.suspicious < t.malicious, { message: "The suspicious threshold must be below the malicious one" });

// The public website: a home page about the service and a price estimator
// for prospective clients, served at / to visitors who aren't signed in.
export const siteSchema = z.object({
  enabled: z.boolean(),
  // Show the estimator and plan prices; off = the home page only.
  estimator: z.boolean(),
  // Let visitors ask the stack advisor; off = rules-only suggestions.
  aiAdvisor: z.boolean(),
  // AI suggestions per day from the website, across all visitors.
  aiDailyLimit: z.number().int().min(0).max(5000),
  // Visitors can send their estimate as a quote request.
  leads: z.boolean(),
  headline: text(140),
  intro: text(600),
});
export type SiteSettings = z.infer<typeof siteSchema>;
export const SITE_DEFAULTS: SiteSettings = { enabled: true, estimator: true, aiAdvisor: true, aiDailyLimit: 100, leads: true, headline: "", intro: "" };

// SMS and WhatsApp alerts (lib/alerts): through Twilio, or a webhook to any
// other gateway (an Indian DLT-registered SMS provider, say). The Twilio
// credentials and the webhook's signing secret are platform secrets.
export const messagingSchema = z.object({
  provider: z.enum(["none", "twilio", "webhook"]),
  // Sender numbers in E.164; WhatsApp needs a WhatsApp-enabled number.
  smsFrom: z.string().trim().regex(/^(\+[1-9]\d{6,14})?$/, "Use the international format, e.g. +919812345678"),
  whatsappFrom: z.string().trim().regex(/^(\+[1-9]\d{6,14})?$/, "Use the international format, e.g. +919812345678"),
  // A Twilio Content template (HX…) for WhatsApp messages that start a
  // conversation: its {{1}} gets the alert's title, {{2}} the link.
  whatsappTemplate: z.string().trim().regex(/^(HX[0-9a-f]{32})?$/i, "A Content SID starts with HX"),
  // https, or plain http only to a gateway on this host.
  webhookUrl: z.string().trim().regex(/^(https:\/\/\S+|http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/\S*)?)?$/, "The gateway must be an https:// URL"),
  // External alerts per person per hour; past it they wait in the app.
  maxPerUserPerHour: z.number().int().min(1).max(200),
});
export type MessagingSettings = z.infer<typeof messagingSchema>;
export const MESSAGING_DEFAULTS: MessagingSettings = { provider: "none", smsFrom: "", whatsappFrom: "", whatsappTemplate: "", webhookUrl: "", maxPerUserPerHour: 20 };

// SOC operations (lib/operations): paging the on-call analyst, weekly QA of
// what the AI did on its own, and the daily digest.
const timeZone = z.string().trim().refine((tz) => {
  try {
    new Intl.DateTimeFormat("en", { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}, "Use an IANA time zone, e.g. Asia/Kolkata");
export const operationsSchema = z.object({
  // Open cases at or above this severity page whoever is on call.
  pageSeverity: z.enum(["MEDIUM", "HIGH", "CRITICAL"]),
  // Minutes before an unacknowledged page goes to the next person.
  ackMinutes: z.number().int().min(2).max(120),
  // Share of each client's AI-handled cases a person reviews each week, and
  // the least per client.
  qaSharePct: z.number().int().min(1).max(100),
  qaMinPerClient: z.number().int().min(0).max(50),
  // The daily digest goes out at this hour, in this time zone.
  digestHour: z.number().int().min(0).max(23),
  timeZone,
});
export type OperationsSettings = z.infer<typeof operationsSchema>;
export const OPERATIONS_DEFAULTS: OperationsSettings = { pageSeverity: "CRITICAL", ackMinutes: 15, qaSharePct: 10, qaMinPerClient: 2, digestHour: 9, timeZone: "Asia/Kolkata" };

// A credential sealed with lib/secrets; only the last 4 characters are kept
// in clear, to show which key is stored.
const sealedSecret = z.object({ sealed: z.string(), last4: z.string() }).nullable().default(null);

const SETTINGS = {
  "ai.killSwitch": z.boolean().default(false),
  "ai.firstResponse.enabled": z.boolean().default(true),
  "ai.firstResponse.minSeverity": z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]).default("MEDIUM"),
  // Blast-radius cap on unattended containment, per tenant per hour.
  "ai.maxAutoActionsPerHour": z.number().int().min(0).max(100).default(5),
  // A test environment holds test data only; every page says so.
  "platform.environment": z.enum(["production", "test"]).default("production"),
  "company.profile": companySchema.default(NO_COMPANY),
  "site.public": siteSchema.default(SITE_DEFAULTS),
  // SIEM detectors switched off by a detection engineer (by name).
  "detection.disabledDetectors": z.array(z.string().max(80)).max(50).default([]),
  // Domains whose links are never analyzed or detonated, on top of the
  // built-in ones and FORENSICS_DOMAIN_WHITELIST.
  "forensics.allowDomains": z.array(z.string().trim().toLowerCase().regex(/^[a-z0-9.-]+\.[a-z]{2,}$/)).max(500).default([]),
  "forensics.thresholds": thresholdsSchema.default({
    malicious: Number(process.env.FORENSICS_MALICIOUS_THRESHOLD ?? 71),
    suspicious: Number(process.env.FORENSICS_SUSPICIOUS_THRESHOLD ?? 31),
  }),
  // Who must use two-step sign-in (an authenticator app); SSO sign-ins
  // leave it to the identity provider.
  "security.mfa": z.enum(["optional", "staff", "everyone"]).default("optional"),
  // With SSO configured, staff can't sign in with a password.
  "security.ssoOnlyForStaff": z.boolean().default(false),
  "secret.virustotal": sealedSecret,
  "secret.abuseipdb": sealedSecret,
  "secret.mxtoolbox": sealedSecret,
  "secret.slackWebhook": sealedSecret,
  "secret.smtp": sealedSecret,
  "secret.twilio": sealedSecret,
  "secret.alertWebhook": sealedSecret,
  "alerts.messaging": messagingSchema.default(MESSAGING_DEFAULTS),
  "operations": operationsSchema.default(OPERATIONS_DEFAULTS),
} as const;

export type SettingKey = keyof typeof SETTINGS;
export type SettingValue<K extends SettingKey> = z.infer<(typeof SETTINGS)[K]>;

export async function getSetting<K extends SettingKey>(key: K): Promise<SettingValue<K>> {
  const row = await db.platformSetting.findUnique({ where: { key } });
  const schema = SETTINGS[key];
  const parsed = schema.safeParse(row?.value ?? undefined);
  return (parsed.success ? parsed.data : schema.parse(undefined)) as SettingValue<K>;
}

export async function setSetting<K extends SettingKey>(key: K, value: SettingValue<K>, actorId?: string) {
  const parsed = SETTINGS[key].parse(value);
  await db.platformSetting.upsert({
    where: { key },
    update: { value: parsed as never, updatedById: actorId },
    create: { key, value: parsed as never, updatedById: actorId },
  });
  return parsed as SettingValue<K>;
}

export async function aiSettings() {
  const [killSwitch, firstResponse, minSeverity, maxAutoActionsPerHour] = await Promise.all([
    getSetting("ai.killSwitch"),
    getSetting("ai.firstResponse.enabled"),
    getSetting("ai.firstResponse.minSeverity"),
    getSetting("ai.maxAutoActionsPerHour"),
  ]);
  return { killSwitch, firstResponse, minSeverity: minSeverity as CaseSeverity, maxAutoActionsPerHour };
}

// Once per request: the shell and pages all ask.
export const platformEnvironment = cache(() => getSetting("platform.environment"));
