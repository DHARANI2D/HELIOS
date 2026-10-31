import { Prisma, type Contract, type ContractKind } from "@prisma/client";
import { z } from "zod";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { getSetting } from "@/lib/settings";
import { notify, staffFor } from "@/lib/notifications";
import { activeRulebook } from "@/lib/rulebook/service";
import { DATA_CATEGORIES } from "@/lib/ingest/health";
import { quoteConfigSchema } from "@/lib/pricing/calculator";
import { CLOSED_STATUSES } from "@/lib/cases/labels";
import { financialYear, gstFor, gstinProblem, invoiceNumber, stateOfGstin, type TaxLine } from "@/lib/billing/gst";
import { CYCLE_MONTHS, PILOT_METRICS, evaluate, formatMoney, invoiceLines, median, periods, termEnd, toMinor, type BillingCycle, type Criterion, type InvoiceLine, type PilotMetric } from "@/lib/billing/terms";

// Contracts, pilots and invoices.
// - A contract is drafted (often from an accepted quote), sent, and signed:
//   in the app by the client's admin, or recorded by staff from paper or an
//   e-signature. Sending and signing snapshot the terms, the DPA reference,
//   the autonomy the client consented to and the rulebook version in force.
// - A pilot is a contract with success criteria measured from the
//   platform's own records over its term; at the end it converts into a
//   subscription draft, or doesn't.
// - The daily job drafts an invoice for each billing period that has
//   started; finance issues it, which numbers it (unique per Indian
//   financial year) and works out GST from the place of supply.

const DAY = 86_400_000;
const text = (max: number) => z.string().trim().max(max);

export const billingProfileSchema = z.object({
  legalName: text(200),
  gstin: z
    .string()
    .trim()
    .toUpperCase()
    .max(15)
    .superRefine((v, ctx) => {
      const problem = v ? gstinProblem(v) : null;
      if (problem) ctx.addIssue({ code: "custom", message: problem });
    })
    .default(""),
  address: text(600),
  // The GST state code of the place of supply when there's no GSTIN.
  state: z.string().regex(/^(\d{2})?$/).default(""),
  country: text(60).default("India"),
  email: z.string().trim().email().or(z.literal("")).default(""),
  poNumber: text(60).default(""),
});
export type BillingProfile = z.infer<typeof billingProfileSchema>;
export const EMPTY_PROFILE: BillingProfile = { legalName: "", gstin: "", address: "", state: "", country: "India", email: "", poNumber: "" };
export const parseProfile = (v: unknown): BillingProfile => ({ ...EMPTY_PROFILE, ...(billingProfileSchema.safeParse(v).data ?? {}) });

export async function saveBillingProfile(tenantId: string, input: unknown, actorId: string) {
  const profile = billingProfileSchema.parse(input);
  await db.tenant.update({ where: { id: tenantId }, data: { billingProfile: profile } });
  await logAction({ actorId, action: "billing.profile_changed", detail: { tenantId, legalName: profile.legalName, gstin: profile.gstin } });
  return profile;
}

const billingStaff = () => staffFor(["SALES", "ADMIN"], null);

// ---------------------------------------------------------------- contracts

const criteriaSchema = z.array(z.object({ metric: z.enum(Object.keys(PILOT_METRICS) as [PilotMetric, ...PilotMetric[]]), target: z.number().min(0).max(1_000_000) })).max(12);
export const parseCriteria = (v: unknown): Criterion[] => criteriaSchema.safeParse(v).data ?? [];

export const contractSchema = z.object({
  kind: z.enum(["PILOT", "SUBSCRIPTION"]),
  currency: z.string().trim().toUpperCase().regex(/^[A-Z]{3}$/, "A three-letter currency code"),
  planName: text(120).default(""),
  // Major units here; stored in minor units.
  monthlyFee: z.number().min(0).max(1e9),
  endpointsCommitted: z.number().int().min(0).max(1e7),
  overagePerEndpoint: z.number().min(0).max(1e7),
  oneTimeFee: z.number().min(0).max(1e9),
  billingCycle: z.enum(Object.keys(CYCLE_MONTHS) as [BillingCycle, ...BillingCycle[]]),
  paymentTermsDays: z.number().int().min(0).max(120),
  startsAt: z.date(),
  months: z.number().int().min(1).max(60),
  autoRenew: z.boolean(),
  noticeDays: z.number().int().min(0).max(365),
  liabilityCapMonths: z.number().int().min(0).max(120),
  successCriteria: criteriaSchema.default([]),
});
export type ContractInput = z.infer<typeof contractSchema>;

async function nextReference(kind: ContractKind, year = new Date().getUTCFullYear()) {
  const prefix = `${kind === "PILOT" ? "P" : "C"}-${year}-`;
  const last = await db.contract.findFirst({ where: { reference: { startsWith: prefix } }, orderBy: { reference: "desc" }, select: { reference: true } });
  return `${prefix}${String((last ? Number.parseInt(last.reference.slice(prefix.length), 10) || 0 : 0) + 1).padStart(4, "0")}`;
}

function contractData(c: ContractInput) {
  return {
    kind: c.kind,
    currency: c.currency,
    planName: c.planName || null,
    monthlyFee: toMinor(c.monthlyFee),
    endpointsCommitted: c.endpointsCommitted,
    overagePerEndpoint: toMinor(c.overagePerEndpoint),
    oneTimeFee: toMinor(c.oneTimeFee),
    billingCycle: c.billingCycle,
    paymentTermsDays: c.paymentTermsDays,
    startsAt: c.startsAt,
    endsAt: termEnd(c.startsAt, c.months),
    termMonths: c.months,
    autoRenew: c.autoRenew,
    noticeDays: c.noticeDays,
    liabilityCapMonths: c.liabilityCapMonths,
    successCriteria: c.kind === "PILOT" ? c.successCriteria : Prisma.DbNull,
  };
}

export async function saveContract(id: string | null, tenantId: string, input: ContractInput, actorId: string, extra: { quoteId?: string | null } = {}) {
  const c = contractSchema.parse(input);
  if (c.kind === "PILOT" && c.months > 6) throw new Error("A pilot runs for six months at most; make it a subscription");
  if (id) {
    const before = await db.contract.findUniqueOrThrow({ where: { id } });
    if (before.status !== "DRAFT") throw new Error("Only a draft can be changed; end it and draft a new one");
    if (before.kind !== c.kind) throw new Error("A draft keeps its kind; draft a new one instead");
    const saved = await db.contract.update({ where: { id }, data: contractData(c) });
    await logAction({ actorId, action: "contract.updated", detail: { contractId: id, reference: saved.reference } });
    return saved;
  }
  if (!(await db.tenant.count({ where: { id: tenantId } }))) throw new Error("Not found");
  for (let attempt = 0; ; attempt++) {
    try {
      const saved = await db.contract.create({ data: { ...contractData(c), tenantId, reference: await nextReference(c.kind), quoteId: extra.quoteId ?? null, createdById: actorId } });
      await logAction({ actorId, action: "contract.created", detail: { contractId: saved.id, reference: saved.reference, tenantId, kind: c.kind } });
      return saved;
    } catch (e) {
      if (attempt < 3 && e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") continue;
      throw e;
    }
  }
}

const TERM_MONTHS = { monthly: 1, annual: 12, "3year": 36 } as const;

// A draft from a quote: its fees, endpoints, plan and term.
export async function contractFromQuote(quoteId: string, tenantId: string | null, startsAt: Date, actorId: string) {
  const quote = await db.quote.findUniqueOrThrow({ where: { id: quoteId } });
  const target = tenantId ?? quote.tenantId;
  if (!target) throw new Error("Choose the client the contract is for");
  const totals = quote.totals as { monthlyNet?: number; oneTime?: number; endpoints?: number; perEndpointMonthly?: number; fxRate?: number; plan?: { name?: string } | null };
  const cfg = quoteConfigSchema.safeParse(quote.config);
  if (!cfg.success) throw new Error("That quote can't be read; open it in Build & Price and save it again");
  const months = TERM_MONTHS[cfg.data.commercial.term] ?? 12;
  // A quote's totals are in USD, shown in its currency at its exchange rate.
  const fx = typeof totals.fxRate === "number" && totals.fxRate > 0 ? totals.fxRate : 1;
  const inQuoteCurrency = (usd: number | undefined) => Math.round((usd ?? 0) * fx * 100) / 100;
  const contract = await saveContract(
    null,
    target,
    {
      kind: "SUBSCRIPTION",
      currency: quote.currency,
      planName: totals.plan?.name ?? "",
      monthlyFee: inQuoteCurrency(totals.monthlyNet),
      endpointsCommitted: totals.endpoints ?? 0,
      overagePerEndpoint: inQuoteCurrency(totals.perEndpointMonthly),
      oneTimeFee: inQuoteCurrency(totals.oneTime),
      billingCycle: months >= 12 ? "quarterly" : "monthly",
      paymentTermsDays: (await getSetting("billing")).paymentTermsDays,
      startsAt,
      months,
      autoRenew: months === 1,
      noticeDays: 30,
      liabilityCapMonths: 12,
      successCriteria: [],
    },
    actorId,
    { quoteId },
  );
  await db.quote.update({ where: { id: quoteId }, data: { status: "ACCEPTED", tenantId: target } });
  return contract;
}

async function snapshot(tenantId: string) {
  const [tenant, book] = await Promise.all([db.tenant.findUniqueOrThrow({ where: { id: tenantId }, select: { aiAutonomyCap: true } }), activeRulebook(tenantId, true)]);
  return { autonomyCap: tenant.aiAutonomyCap, rulebookVersion: book?.version ?? null };
}

export async function sendContract(id: string, actorId: string) {
  const c = await db.contract.findUniqueOrThrow({ where: { id } });
  if (c.status !== "DRAFT") throw new Error("Only a draft is sent");
  const settings = await getSetting("billing");
  if (!settings.contractTerms.trim()) throw new Error("Add your terms of service under Contracts & Billing → Settings first (your counsel's text)");
  const sent = await db.contract.update({ where: { id }, data: { status: "SENT", sentAt: new Date(), terms: settings.contractTerms, dpaReference: settings.dpaReference || null, ...(await snapshot(c.tenantId)) } });
  const admins = await db.user.findMany({ where: { tenantId: c.tenantId, role: "CLIENT_ADMIN", active: true }, select: { id: true } });
  await notify(admins.map((a) => a.id), { kind: "billing", title: `${c.kind === "PILOT" ? "Pilot" : "Contract"} ${c.reference} is ready to sign`, body: `${c.planName ?? "Managed detection and response"} from ${c.startsAt.toISOString().slice(0, 10)} to ${c.endsAt.toISOString().slice(0, 10)}.`, href: `/billing/contracts/${id}` });
  await logAction({ actorId, action: "contract.sent", detail: { contractId: id, reference: c.reference } });
  return sent;
}

export async function signContract(id: string, input: { name: string; title: string; via: "in_app" | "paper" | "e_sign" }, actor: { id: string; isClient: boolean; tenantId: string | null }) {
  const c = await db.contract.findUniqueOrThrow({ where: { id } });
  if (c.status !== "SENT") throw new Error("Only a contract that was sent can be signed");
  if (actor.isClient ? actor.tenantId !== c.tenantId || input.via !== "in_app" : input.via === "in_app") throw new Error(actor.isClient ? "Not found" : "Staff record a signature given on paper or by e-signature");
  if (input.name.trim().length < 2) throw new Error("Name who signed");
  // Signing confirms what was sent: if the rulebook or the autonomy consent
  // changed since, send it again.
  const now = await snapshot(c.tenantId);
  if (now.rulebookVersion !== c.rulebookVersion || now.autonomyCap !== c.autonomyCap) throw new Error("The client's rulebook or AI autonomy consent changed after this was sent: send it again so the signature covers what's in force");
  const signed = await db.contract.update({ where: { id }, data: { status: "ACTIVE", signedAt: new Date(), signedByName: input.name.trim().slice(0, 120), signedByTitle: input.title.trim().slice(0, 120) || null, signedVia: input.via, signedRecordedById: actor.id } });
  await notify(await billingStaff(), { kind: "billing", title: `${c.reference} signed by ${input.name.trim()}`, body: `${c.kind === "PILOT" ? "Pilot" : "Contract"} active from ${c.startsAt.toISOString().slice(0, 10)}.`, href: `/billing/contracts/${id}` }, { exclude: actor.id });
  await logAction({ actorId: actor.id, action: "contract.signed", detail: { contractId: id, reference: c.reference, by: input.name, title: input.title, via: input.via, rulebookVersion: c.rulebookVersion, autonomyCap: c.autonomyCap } });
  return signed;
}

export async function endContract(id: string, reason: string, actorId: string, terminate: boolean) {
  const c = await db.contract.findUniqueOrThrow({ where: { id } });
  if (!["DRAFT", "SENT", "ACTIVE"].includes(c.status)) throw new Error("It has already ended");
  if (reason.trim().length < 3) throw new Error("Say why");
  await db.contract.update({ where: { id }, data: { status: terminate ? "TERMINATED" : "ENDED", endedAt: new Date(), endReason: reason.trim().slice(0, 1000) } });
  await logAction({ actorId, action: terminate ? "contract.terminated" : "contract.ended", detail: { contractId: id, reference: c.reference, reason } });
}

// A pilot that went well becomes a subscription draft starting when it ends.
export async function convertPilot(id: string, actorId: string) {
  const p = await db.contract.findUniqueOrThrow({ where: { id } });
  if (p.kind !== "PILOT" || !["ACTIVE", "ENDED"].includes(p.status)) throw new Error("Only a signed pilot converts");
  if (p.convertedToId) throw new Error("It has already been converted");
  const sub = await saveContract(null, p.tenantId, {
    kind: "SUBSCRIPTION",
    currency: p.currency,
    planName: p.planName ?? "",
    monthlyFee: p.monthlyFee / 100,
    endpointsCommitted: p.endpointsCommitted,
    overagePerEndpoint: p.overagePerEndpoint / 100,
    oneTimeFee: 0,
    billingCycle: "quarterly",
    paymentTermsDays: p.paymentTermsDays,
    startsAt: p.endsAt,
    months: 12,
    autoRenew: false,
    noticeDays: 30,
    liabilityCapMonths: p.liabilityCapMonths,
    successCriteria: [],
  }, actorId);
  await db.contract.update({ where: { id }, data: { pilotOutcome: "converted", convertedToId: sub.id } });
  await logAction({ actorId, action: "contract.pilot_converted", detail: { pilotId: id, contractId: sub.id } });
  return sub;
}

export async function recordPilotOutcome(id: string, outcome: "not_converted", actorId: string) {
  await db.contract.update({ where: { id }, data: { pilotOutcome: outcome } });
  await logAction({ actorId, action: "contract.pilot_outcome", detail: { pilotId: id, outcome } });
}

// ---------------------------------------------------------------- pilot metrics

export async function pilotValues(tenantId: string, from: Date, to: Date): Promise<Record<PilotMetric, number | null>> {
  const range = { gte: from, lt: to };
  const [cases, outcomes, sources, qa, closed] = await Promise.all([
    db.case.findMany({ where: { tenantId, createdAt: range }, select: { createdAt: true, acknowledgedAt: true, containedAt: true, slaDueAt: true } }),
    db.aiDecisionOutcome.findMany({ where: { tenantId, kind: "action", createdAt: range, aiOutcome: { not: "NONE" } }, select: { agreed: true, falseContainment: true, critical: true } }),
    db.integration.findMany({ where: { tenantId, enabled: true }, select: { category: true, lastEventAt: true, quietSince: true } }),
    db.qaReview.findMany({ where: { tenantId, status: "DONE", reviewedAt: range }, select: { outcome: true } }),
    db.case.count({ where: { tenantId, status: { in: CLOSED_STATUSES }, resolvedAt: range } }),
  ]);
  const mins = (a: Date, b: Date) => (b.getTime() - a.getTime()) / 60_000;
  const acked = cases.filter((c) => c.acknowledgedAt);
  const withSla = acked.filter((c) => c.slaDueAt);
  const data = sources.filter((s) => DATA_CATEGORIES.has(s.category));
  const pct = (n: number, d: number) => (d ? Math.round((n / d) * 1000) / 10 : null);
  const round = (v: number | null) => (v == null ? null : Math.round(v * 10) / 10);
  return {
    mtta_minutes: round(median(acked.map((c) => mins(c.createdAt, c.acknowledgedAt!)))),
    mttc_minutes: round(median(cases.filter((c) => c.containedAt).map((c) => mins(c.createdAt, c.containedAt!)))),
    sla_ack_pct: pct(withSla.filter((c) => c.acknowledgedAt! <= c.slaDueAt!).length, withSla.length),
    ai_agreement_pct: pct(outcomes.filter((o) => o.agreed).length, outcomes.length),
    // No AI decisions yet is no data, not a clean record.
    false_containments: outcomes.length ? outcomes.filter((o) => o.falseContainment).length : null,
    critical_false_containments: outcomes.length ? outcomes.filter((o) => o.falseContainment && o.critical).length : null,
    sources_live_pct: pct(data.filter((s) => s.lastEventAt && !s.quietSince && to.getTime() - s.lastEventAt.getTime() < DAY).length, data.length),
    qa_agreement_pct: pct(qa.filter((q) => q.outcome === "agree").length, qa.length),
    cases_handled: closed,
  };
}

export async function pilotReport(c: Pick<Contract, "tenantId" | "startsAt" | "endsAt" | "successCriteria">, now = new Date()) {
  const to = now < c.endsAt ? now : c.endsAt;
  const values = await pilotValues(c.tenantId, c.startsAt, to);
  return { values, criteria: evaluate(parseCriteria(c.successCriteria), values) };
}

// ---------------------------------------------------------------- invoices

// Drafts an invoice for each billing period of an active contract that has
// started. Safe to repeat: one invoice per contract and period.
export async function generateInvoices(now = new Date()) {
  const contracts = await db.contract.findMany({ where: { status: "ACTIVE", startsAt: { lte: now } } });
  let drafted = 0;
  for (const c of contracts) {
    const due = periods(c.startsAt, c.endsAt, c.billingCycle as BillingCycle).filter((p) => p.from <= now && (!c.billedThrough || p.from >= c.billedThrough));
    if (!due.length) continue;
    const endpoints = await db.endpoint.count({ where: { tenantId: c.tenantId } });
    let invoiced = await db.invoice.count({ where: { contractId: c.id, status: { not: "VOID" } } });
    for (const p of due) {
      const lines = invoiceLines({ planName: c.planName, cycle: c.billingCycle as BillingCycle, monthlyFee: c.monthlyFee, endpointsCommitted: c.endpointsCommitted, overagePerEndpoint: c.overagePerEndpoint, oneTimeFee: c.oneTimeFee }, p, endpoints, invoiced === 0);
      if (lines.length) {
        const subtotal = lines.reduce((n, l) => n + l.amount, 0);
        try {
          await db.invoice.create({ data: { tenantId: c.tenantId, contractId: c.id, currency: c.currency, periodFrom: p.from, periodTo: p.to, lines: lines as unknown as Prisma.InputJsonValue, subtotal, total: subtotal } });
          drafted++;
          invoiced++;
        } catch (e) {
          if (!(e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002")) throw e;
        }
      }
      await db.contract.update({ where: { id: c.id }, data: { billedThrough: p.to } });
    }
  }
  if (drafted) await notify(await billingStaff(), { kind: "billing", title: `${drafted} invoice${drafted === 1 ? "" : "s"} drafted`, body: "Check and issue them under Contracts & Billing.", href: "/billing#invoices" });
  return drafted;
}

async function companyParty() {
  const company = await getSetting("company.profile");
  const gstin = company.taxId.trim().toUpperCase();
  return { name: company.legalName || company.name, address: company.address, gstin: gstin && !gstinProblem(gstin) ? gstin : null, state: stateOfGstin(gstin), email: company.email, phone: company.phone };
}

// Numbers the draft and works out its tax; it can't change after this.
export async function issueInvoice(id: string, actorId: string, now = new Date()) {
  const inv = await db.invoice.findUniqueOrThrow({ where: { id }, include: { contract: { select: { paymentTermsDays: true } } } });
  if (inv.status !== "DRAFT") throw new Error("Only a draft is issued");
  const tenant = await db.tenant.findUniqueOrThrow({ where: { id: inv.tenantId }, select: { name: true, billingProfile: true } });
  const to = parseProfile(tenant.billingProfile);
  if (!to.legalName || !to.address) throw new Error("Add the client's billing name and address first");
  const inIndia = !to.country || /^india$/i.test(to.country.trim());
  const recipientState = stateOfGstin(to.gstin) ?? (to.state || null);
  const [settings, from] = await Promise.all([getSetting("billing"), companyParty()]);
  if (settings.gstRatePct > 0 && !from.gstin) throw new Error("Add your company's GSTIN as the tax id in Settings → Company profile, or set the GST rate to 0");
  if (!from.name || !from.address) throw new Error("Add your company's legal name and address in Settings → Company profile");
  const tax = gstFor({ supplierState: from.state, recipientState, recipientInIndia: inIndia, ratePct: settings.gstRatePct }, inv.subtotal);
  if ((tax.mode === "intra" || tax.mode === "inter") && inv.currency !== "INR") throw new Error("A GST invoice to a client in India is in rupees: draft the contract in INR");
  const taxTotal = tax.lines.reduce((n, l) => n + l.amount, 0);
  const fy = financialYear(now);
  const prefix = `${settings.invoicePrefix}/${fy}/`;
  for (let attempt = 0; ; attempt++) {
    const last = await db.invoice.findFirst({ where: { number: { startsWith: prefix } }, orderBy: { number: "desc" }, select: { number: true } });
    const number = invoiceNumber(settings.invoicePrefix, fy, (last ? Number.parseInt(last.number!.slice(prefix.length), 10) || 0 : 0) + 1);
    try {
      const { count } = await db.invoice.updateMany({
        where: { id, status: "DRAFT" },
        data: {
          number,
          status: "ISSUED",
          issuedAt: now,
          dueAt: new Date(now.getTime() + (inv.contract?.paymentTermsDays ?? settings.paymentTermsDays) * DAY),
          taxMode: tax.mode,
          taxLines: tax.lines as unknown as Prisma.InputJsonValue,
          total: inv.subtotal + taxTotal,
          sac: settings.sac || null,
          supplier: from,
          recipient: { ...to, name: to.legalName || tenant.name, state: recipientState, inIndia },
        },
      });
      if (!count) throw new Error("Only a draft is issued");
      await logAction({ actorId, action: "invoice.issued", detail: { invoiceId: id, number, total: inv.subtotal + taxTotal, currency: inv.currency } });
      return number;
    } catch (e) {
      if (attempt < 3 && e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") continue;
      throw e;
    }
  }
}

export async function markPaid(id: string, input: { reference: string; paidAt: Date }, actorId: string) {
  const { count } = await db.invoice.updateMany({ where: { id, status: "ISSUED" }, data: { status: "PAID", paidAt: input.paidAt, paymentRef: input.reference.trim().slice(0, 120) || null } });
  if (!count) throw new Error("Only an issued invoice is paid");
  await logAction({ actorId, action: "invoice.paid", detail: { invoiceId: id, reference: input.reference, paidAt: input.paidAt } });
}

// An issued invoice keeps its number and is voided with a reason; a draft
// is simply discarded.
export async function voidInvoice(id: string, reason: string, actorId: string) {
  const inv = await db.invoice.findUniqueOrThrow({ where: { id } });
  if (inv.status === "DRAFT") {
    await db.invoice.delete({ where: { id } });
    await logAction({ actorId, action: "invoice.discarded", detail: { invoiceId: id, periodFrom: inv.periodFrom } });
    return "discarded";
  }
  if (inv.status !== "ISSUED") throw new Error("Only an issued invoice is voided");
  if (reason.trim().length < 3) throw new Error("Say why");
  await db.invoice.update({ where: { id }, data: { status: "VOID", voidedAt: new Date(), voidReason: reason.trim().slice(0, 500) } });
  await logAction({ actorId, action: "invoice.voided", detail: { invoiceId: id, number: inv.number, reason } });
  return "voided";
}

export const invoiceLinesOf = (v: Prisma.JsonValue) => (Array.isArray(v) ? (v as unknown as InvoiceLine[]) : []);
export const taxLinesOf = (v: Prisma.JsonValue | null) => (Array.isArray(v) ? (v as unknown as TaxLine[]) : []);

// ---------------------------------------------------------------- the daily job

export async function commercialClocks(now = new Date()) {
  const drafted = await generateInvoices(now);
  const staff = await billingStaff();
  let reminders = 0;

  // Overdue invoices, once a week each.
  const overdue = await db.invoice.findMany({ where: { status: "ISSUED", dueAt: { lt: now }, OR: [{ remindedAt: null }, { remindedAt: { lt: new Date(now.getTime() - 7 * DAY) } }] }, include: { contract: { select: { reference: true } } } });
  for (const inv of overdue) {
    const { count } = await db.invoice.updateMany({ where: { id: inv.id, remindedAt: inv.remindedAt }, data: { remindedAt: now } });
    if (!count) continue;
    await notify(staff, { kind: "billing", title: `Invoice ${inv.number} is overdue`, body: `${formatMoney(inv.total, inv.currency)}, due ${inv.dueAt!.toISOString().slice(0, 10)}.`, href: `/billing#invoices` });
    reminders++;
  }

  // Renewals coming up (two weeks before the notice deadline) and pilots ending in a week.
  const active = await db.contract.findMany({ where: { status: "ACTIVE", remindedAt: null } });
  for (const c of active) {
    const noticeBy = new Date(c.endsAt.getTime() - c.noticeDays * DAY);
    const due = c.kind === "PILOT" ? c.endsAt.getTime() - 7 * DAY <= now.getTime() : noticeBy.getTime() - 14 * DAY <= now.getTime();
    if (!due) continue;
    const { count } = await db.contract.updateMany({ where: { id: c.id, remindedAt: null }, data: { remindedAt: now } });
    if (!count) continue;
    if (c.kind === "PILOT") {
      const r = await pilotReport(c, now);
      const met = r.criteria.filter((x) => x.met).length;
      await notify(staff, { kind: "billing", title: `Pilot ${c.reference} ends ${c.endsAt.toISOString().slice(0, 10)}`, body: `${met} of ${r.criteria.length} success criteria met so far. Convert it or record that it won't continue.`, href: `/billing/contracts/${c.id}` });
    } else {
      await notify(staff, { kind: "billing", title: `${c.reference} ${c.autoRenew ? "renews" : "ends"} ${c.endsAt.toISOString().slice(0, 10)}`, body: `Notice is due by ${noticeBy.toISOString().slice(0, 10)}.`, href: `/billing/contracts/${c.id}` });
    }
    reminders++;
  }

  // Terms that have run out: renew or end.
  let renewed = 0;
  let ended = 0;
  for (const c of await db.contract.findMany({ where: { status: "ACTIVE", endsAt: { lte: now } } })) {
    if (c.autoRenew && c.kind === "SUBSCRIPTION") {
      await db.contract.update({ where: { id: c.id }, data: { endsAt: termEnd(c.endsAt, c.termMonths), remindedAt: null } });
      await logAction({ action: "contract.renewed", detail: { contractId: c.id, reference: c.reference, months: c.termMonths } });
      renewed++;
    } else {
      await db.contract.update({ where: { id: c.id }, data: { status: "ENDED", endedAt: now, endReason: "The term ended" } });
      await logAction({ action: "contract.ended", detail: { contractId: c.id, reference: c.reference, reason: "term ended" } });
      ended++;
    }
  }
  return { drafted, reminders, renewed, ended };
}
