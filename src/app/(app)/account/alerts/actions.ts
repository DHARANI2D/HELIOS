"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { db } from "@/lib/db";
import { requireUser } from "@/lib/session";
import { logAction } from "@/lib/audit";
import { sendAlert } from "@/lib/alerts/send";
import { ALERT_GROUPS, CHANNEL_KEYS, E164, channelsFor, parsePrefs, prefsFromGroups, type AlertChannel, type AlertGroup } from "@/lib/alerts/kinds";
import { action } from "@/lib/action";

// Each person's own alert channels: a phone number for texts, and which
// kinds of notification also go out by email, SMS or WhatsApp.

const channel = z.enum(CHANNEL_KEYS as [AlertChannel, ...AlertChannel[]]);
const prefsInput = z.object({
  phone: z.string().trim().transform((v) => v.replace(/[\s-]/g, "")).refine((v) => v === "" || E164.test(v), "Use the international format, e.g. +919812345678"),
  groups: z.object(Object.fromEntries(ALERT_GROUPS.map((g) => [g.key, z.array(channel).max(3).default([])])) as Record<AlertGroup, z.ZodDefault<z.ZodArray<typeof channel>>>),
});

export const saveAlertPrefsAction = action(async function saveAlertPrefsAction(input: z.input<typeof prefsInput>) {
  const user = await requireUser();
  const parsed = prefsInput.safeParse(input);
  if (!parsed.success) throw new Error(parsed.error.issues[0]?.message ?? "Check the form");
  const { phone, groups } = parsed.data;
  const prefs = prefsFromGroups(groups);
  const texts = Object.values(prefs).some((c) => c.includes("sms") || c.includes("whatsapp"));
  if (texts && !phone) throw new Error("Add a phone number for SMS or WhatsApp alerts");
  await db.user.update({ where: { id: user.id }, data: { phone: phone || null, alertPrefs: prefs } });
  await logAction({ actorId: user.id, action: "account.alerts_changed", detail: { channels: [...new Set(Object.values(prefs).flat())], phoneSet: !!phone } });
  revalidatePath("/account/alerts");
});

// Sends one test now on each channel the person uses, so they know it arrives.
export const testAlertsAction = action(async function testAlertsAction() {
  const user = await requireUser();
  const me = await db.user.findUniqueOrThrow({ where: { id: user.id }, select: { email: true, phone: true, alertPrefs: true } });
  const prefs = parsePrefs(me.alertPrefs);
  const used = [...new Set(ALERT_GROUPS.flatMap((g) => channelsFor(prefs, g.kinds[0])))];
  if (!used.length) throw new Error("Pick at least one channel first");
  const results: Array<{ channel: AlertChannel; ok: boolean; message: string }> = [];
  for (const c of used) {
    const to = c === "email" ? me.email : me.phone;
    if (!to) {
      results.push({ channel: c, ok: false, message: "No phone number on your account" });
      continue;
    }
    const r = await sendAlert(c, to, { subject: "Test alert", body: "This is how HELIOS alerts will reach you.", link: `${process.env.AUTH_URL ?? ""}/account/alerts` });
    results.push({ channel: c, ok: r.ok, message: r.ok ? `Sent to ${to}` : r.error ?? "Not sent" });
  }
  await logAction({ actorId: user.id, action: "account.alerts_tested", detail: { results: results.map((r) => ({ channel: r.channel, ok: r.ok })) } });
  return results;
});
