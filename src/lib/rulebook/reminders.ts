import { db } from "@/lib/db";
import { notify, staffFor } from "@/lib/notifications";
import { claimOnce } from "@/lib/jobs/once";
import { parseStored } from "@/lib/rulebook/service";

// A signed rulebook is reviewed every so often (90 days unless the client
// sets otherwise). Its client admins and the SOC managers hear two weeks
// before the date and again once it's past; allowlist entries hear a week
// before they lapse. Each reminder goes once (claimed, so two instances
// don't both send it).

const DAY = 86_400_000;
const SOON_DAYS = 14;
const ALLOWLIST_DAYS = 7;
const day = (d: Date) => d.toISOString().slice(0, 10);

async function audience(tenantId: string) {
  const admins = await db.user.findMany({ where: { tenantId, role: "CLIENT_ADMIN", active: true }, select: { id: true } });
  return [...admins.map((a) => a.id), ...(await staffFor(["SOC_MANAGER"], null))];
}

export async function remindRulebookReviews(now = new Date()) {
  let sent = 0;
  const active = await db.orgPolicy.findMany({ where: { status: "ACTIVE", signedAt: { not: null } }, include: { tenant: { select: { name: true } } } });
  for (const row of active) {
    const every = parseStored(row).reviewEveryDays;
    const due = new Date(row.signedAt!.getTime() + every * DAY);
    if (now.getTime() < due.getTime() - SOON_DAYS * DAY) continue;
    const stage = now >= due ? "overdue" : "soon";
    if (!(await claimOnce(`rulebook.review:${row.tenantId}:v${row.version}:${stage}`))) continue;
    await notify(await audience(row.tenantId), {
      kind: "rulebook",
      title: stage === "overdue" ? `${row.tenant.name}'s rulebook review is overdue (due ${day(due)})` : `${row.tenant.name}'s rulebook is due for review on ${day(due)}`,
      body: `Version ${row.version} was signed ${day(row.signedAt!)}; the client reviews it every ${every} days. Re-signing it unchanged counts as a review.`,
      href: `/rulebook?tenant=${row.tenantId}`,
    });
    sent++;
  }
  const lapsing = await db.policyAllowlistEntry.findMany({ where: { expiresAt: { gt: now, lte: new Date(now.getTime() + ALLOWLIST_DAYS * DAY) } } });
  for (const e of lapsing) {
    if (!(await claimOnce(`allowlist.lapsing:${e.id}:${e.expiresAt!.toISOString()}`))) continue;
    await notify(await audience(e.tenantId), {
      kind: "rulebook",
      title: `Allowlist entry ${e.value} lapses on ${day(e.expiresAt!)}`,
      body: `${e.reason} (owner ${e.owner}). Extend it on the rulebook page if it's still needed; once it lapses, HELIOS treats ${e.value} like anything else.`,
      href: `/rulebook?tenant=${e.tenantId}`,
    });
    sent++;
  }
  return sent;
}
