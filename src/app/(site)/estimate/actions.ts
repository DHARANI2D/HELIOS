"use server";

import { z } from "zod";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { notify } from "@/lib/notifications";
import { ROLE_ORDER, can } from "@/lib/rbac";
import { clientAddress, rateLimit } from "@/lib/rate-limit";
import { publicPricingContext, siteSettings } from "@/lib/site";
import { publicConfig } from "@/lib/pricing/public";
import { calculateQuote, formatMoney, type QuoteConfig } from "@/lib/pricing/calculator";
import { loadPricingContext } from "@/lib/pricing/service";
import { createQuote } from "@/lib/pricing/quotes";
import { describeMix } from "@/lib/pricing/endpoint-mix";
import { runAdvisorAgent, type AiAdvice } from "@/lib/pricing/advisor-agent";
import type { AdvisorGoal } from "@/lib/pricing/advisor";
import { action } from "@/lib/action";

// The public estimator's two server actions. Anyone can call them, so each
// checks the site settings, validates everything, and is rate limited per
// visitor; AI answers also share a daily budget across all visitors.

const DAY = 24 * 60 * 60 * 1000;
const goalSchema = z.enum(["balanced", "budget", "protection"]);

async function openSite() {
  const site = await siteSettings();
  if (!site.enabled || !site.estimator) throw new Error("The estimator isn't available right now.");
  return site;
}

export const publicAdviceAction = action(async function publicAdviceAction(input: QuoteConfig, goalInput: AdvisorGoal): Promise<AiAdvice> {
  const site = await openSite();
  if (!site.aiAdvisor) throw new Error("The AI advisor is switched off.");
  const ctx = await publicPricingContext();
  const cfg = publicConfig(input, ctx);
  const goal = goalSchema.parse(goalInput);
  const ip = await clientAddress();
  if (!rateLimit(`advice:${ip}`, 6, 10 * 60 * 1000).ok) throw new Error("You've asked the advisor several times in a row. Try again in a few minutes.");

  const usedToday = await db.aiRun.count({ where: { agentKey: "advisor", trigger: "website", createdAt: { gte: new Date(Date.now() - DAY) } } });
  const rulesOnly = usedToday >= site.aiDailyLimit ? "The AI advisor has answered as many questions as it can today; these are the rules' suggestions." : undefined;
  return runAdvisorAgent(cfg, ctx, goal, { audience: "public", trigger: "website", rulesOnly });
});

const contactSchema = z.object({
  name: z.string().trim().min(2, "Your name, please").max(120),
  email: z.string().trim().toLowerCase().email("A valid email address, please").max(200),
  company: z.string().trim().min(2, "Your organization's name, please").max(160),
  phone: z.string().trim().max(40).default(""),
  message: z.string().trim().max(2000).default(""),
  consent: z.literal(true, { message: "Please agree to be contacted about this estimate" }),
  // Hidden from people; bots fill it in.
  website: z.string().max(200).default(""),
});
export type QuoteRequestInput = z.input<typeof contactSchema>;

export const requestQuoteAction = action(async function requestQuoteAction(input: QuoteConfig, contactInput: QuoteRequestInput): Promise<{ reference: string | null }> {
  const site = await openSite();
  if (!site.leads) throw new Error("Quote requests are switched off; please contact us directly.");
  const contact = contactSchema.parse(contactInput);
  if (contact.website) return { reference: null };
  const ip = await clientAddress();
  if (!rateLimit(`lead:${ip}`, 3, 60 * 60 * 1000).ok) throw new Error("We've already received several requests from you. We'll be in touch.");
  const today = await db.quote.count({ where: { source: "website", createdAt: { gte: new Date(Date.now() - DAY) } } });
  if (today >= 50) throw new Error("We can't take more requests online today; please email or call us.");

  // Priced with the full price book, so the team sees margins on it.
  const ctx = await loadPricingContext();
  const cfg = { ...publicConfig(input, ctx), clientName: contact.company };
  const totals = calculateQuote(cfg, ctx);
  const quote = await createQuote({
    clientName: contact.company,
    currency: totals.currency,
    config: JSON.parse(JSON.stringify(cfg)),
    totals: JSON.parse(JSON.stringify(totals)),
    notes: contact.message || null,
    source: "website",
    contactName: contact.name,
    contactEmail: contact.email,
    contactPhone: contact.phone || null,
    validUntil: new Date(Date.now() + 30 * DAY),
  });
  await logAction({ action: "quote.requested", detail: { quoteId: quote.id, reference: quote.reference, source: "website", endpoints: totals.endpoints, monthlyNet: totals.monthlyNet } });

  const roles = ROLE_ORDER.filter((r) => can({ role: r }, "pricing.view") && !r.startsWith("CLIENT_"));
  const staff = await db.user.findMany({ where: { active: true, tenantId: null, role: { in: roles } }, select: { id: true } });
  await notify(staff.map((u) => u.id), {
    kind: "lead",
    title: `Quote request from ${contact.company}`,
    body: `${contact.name} <${contact.email}> · ${cfg.profile.mix ? describeMix(cfg.profile.mix) : `${totals.endpoints} endpoints`} · estimate ${formatMoney(totals.monthlyNet, totals.currency, totals.fxRate, { decimals: 0 })}/month${totals.missing.length ? ` (${totals.missing.length} price${totals.missing.length === 1 ? "" : "s"} to set)` : ""}`,
    href: `/pricing/quotes/${quote.id}`,
  });
  return { reference: quote.reference };
});
