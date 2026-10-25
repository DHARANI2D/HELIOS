"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { logAction } from "@/lib/audit";
import { requirePermission } from "@/lib/session";
import { companySchema, getSetting, setSetting, siteSchema, thresholdsSchema } from "@/lib/settings";
import { PLATFORM_SECRETS, storePlatformSecret, type PlatformSecret } from "@/lib/platform-secrets";

function revalidate() {
  revalidatePath("/settings");
  revalidatePath("/", "layout");
}

export async function saveCompanyAction(input: z.input<typeof companySchema>) {
  const user = await requirePermission("settings.manage");
  const profile = companySchema.parse(input);
  await setSetting("company.profile", profile, user.id);
  await logAction({ actorId: user.id, action: "settings.company_changed", detail: { name: profile.name } });
  revalidate();
}

export async function saveSiteAction(input: z.input<typeof siteSchema>) {
  const user = await requirePermission("settings.manage");
  const site = siteSchema.parse(input);
  await setSetting("site.public", site, user.id);
  await logAction({ actorId: user.id, action: "settings.site_changed", detail: { enabled: site.enabled, estimator: site.estimator, aiAdvisor: site.aiAdvisor, aiDailyLimit: site.aiDailyLimit, leads: site.leads } });
  revalidate();
  revalidatePath("/home");
  revalidatePath("/estimate");
}

// Only a platform admin moves the whole database between production and
// test, since it changes how every page presents its data.
export async function setEnvironmentAction(environment: "production" | "test") {
  const user = await requirePermission("settings.manage");
  if (user.role !== "ADMIN") throw new Error("Only a platform admin can change the environment");
  const to = z.enum(["production", "test"]).parse(environment);
  const from = await getSetting("platform.environment");
  if (from === to) return;
  await setSetting("platform.environment", to, user.id);
  await logAction({ actorId: user.id, action: "platform.environment_changed", detail: { from, to } });
  revalidate();
}

const secretName = z.enum(Object.keys(PLATFORM_SECRETS) as [PlatformSecret, ...PlatformSecret[]]);

// Never echoes the value back; the audit entry records only which key changed.
export async function savePlatformSecretAction(name: string, value: string | null) {
  const user = await requirePermission("settings.manage");
  const key = secretName.parse(name);
  const v = value === null ? null : z.string().trim().min(8, "That doesn't look like a complete key").max(2000).parse(value);
  if (key === "slackWebhook" && v && !/^https:\/\//i.test(v)) throw new Error("The webhook must be an https:// URL");
  await storePlatformSecret(key, v, user.id);
  await logAction({ actorId: user.id, action: v ? "settings.secret_stored" : "settings.secret_cleared", detail: { secret: key } });
  revalidate();
}

const forensicsSchema = z.object({
  thresholds: thresholdsSchema,
  allowDomains: z.array(z.string()).max(500),
});

export async function saveForensicsSettingsAction(input: z.input<typeof forensicsSchema>) {
  const user = await requirePermission("settings.manage");
  const s = forensicsSchema.parse(input);
  const domains = [...new Set(s.allowDomains.map((d) => d.trim().toLowerCase().replace(/^\*\./, "")).filter(Boolean))];
  const bad = domains.filter((d) => !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d));
  if (bad.length) throw new Error(`Not a domain: ${bad.slice(0, 3).join(", ")}`);
  await setSetting("forensics.thresholds", s.thresholds, user.id);
  await setSetting("forensics.allowDomains", domains, user.id);
  await logAction({ actorId: user.id, action: "settings.forensics_changed", detail: { thresholds: s.thresholds, allowDomains: domains.length } });
  revalidate();
}
