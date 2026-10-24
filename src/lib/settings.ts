import type { CaseSeverity } from "@prisma/client";
import { z } from "zod";

import { db } from "@/lib/db";

// Platform-wide switches, stored in platform_settings and edited from the AI
// Agents page. Defaults apply until someone saves a value.

const SETTINGS = {
  "ai.killSwitch": z.boolean().default(false),
  "ai.firstResponse.enabled": z.boolean().default(true),
  "ai.firstResponse.minSeverity": z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]).default("MEDIUM"),
  // Blast-radius cap on unattended containment, per tenant per hour.
  "ai.maxAutoActionsPerHour": z.number().int().min(0).max(100).default(5),
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
