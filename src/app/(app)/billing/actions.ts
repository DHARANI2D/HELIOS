"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { requirePermission, requireUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { logAction } from "@/lib/audit";
import { billingSchema, setSetting } from "@/lib/settings";
import { contractFromQuote, contractSchema, convertPilot, endContract, generateInvoices, issueInvoice, markPaid, recordPilotOutcome, saveBillingProfile, saveContract, sendContract, signContract, voidInvoice } from "@/lib/billing/service";
import { action } from "@/lib/action";

// Contracts, pilots and invoices: account managers and admins; a client's
// admin signs their own contract in the app.

const id = z.string().min(1);
const date = z.iso.date().transform((s) => new Date(`${s}T00:00:00Z`));
const done = (contractId?: string) => {
  revalidatePath("/billing");
  if (contractId) revalidatePath(`/billing/contracts/${contractId}`);
};

type ContractForm = Omit<z.input<typeof contractSchema>, "startsAt"> & { startsAt: string };

export const saveContractAction = action(async function saveContractAction(contractId: string | null, tenantId: string, input: ContractForm) {
  const user = await requirePermission("billing.manage");
  const saved = await saveContract(contractId ? id.parse(contractId) : null, id.parse(tenantId), contractSchema.parse({ ...input, startsAt: date.parse(input.startsAt) }), user.id);
  done(saved.id);
  return saved.id;
});

export const contractFromQuoteAction = action(async function contractFromQuoteAction(quoteId: string, tenantId: string | null, startsAt: string) {
  const user = await requirePermission("billing.manage");
  const c = await contractFromQuote(id.parse(quoteId), tenantId || null, date.parse(startsAt), user.id);
  done(c.id);
  revalidatePath("/pricing");
  return c.id;
});

export const sendContractAction = action(async function sendContractAction(contractId: string) {
  const user = await requirePermission("billing.manage");
  await sendContract(id.parse(contractId), user.id);
  done(contractId);
});

// A client's admin signs in the app; staff record a signature given on
// paper or by e-signature.
export const signContractAction = action(async function signContractAction(contractId: string, input: { name: string; title: string; via: string }) {
  const user = await requireUser();
  if (user.isClient ? user.role !== "CLIENT_ADMIN" : !can(user, "billing.manage")) throw new Error("You don't have permission to do that");
  await signContract(id.parse(contractId), { name: z.string().max(120).parse(input.name), title: z.string().max(120).parse(input.title ?? ""), via: z.enum(["in_app", "paper", "e_sign"]).parse(user.isClient ? "in_app" : input.via) }, { id: user.id, isClient: user.isClient, tenantId: user.tenantId });
  done(contractId);
});

export const endContractAction = action(async function endContractAction(contractId: string, reason: string, terminate: boolean) {
  const user = await requirePermission("billing.manage");
  await endContract(id.parse(contractId), z.string().max(1000).parse(reason), user.id, !!terminate);
  done(contractId);
});

export const convertPilotAction = action(async function convertPilotAction(contractId: string) {
  const user = await requirePermission("billing.manage");
  const sub = await convertPilot(id.parse(contractId), user.id);
  done(contractId);
  return sub.id;
});

export const pilotNotConvertedAction = action(async function pilotNotConvertedAction(contractId: string) {
  const user = await requirePermission("billing.manage");
  await recordPilotOutcome(id.parse(contractId), "not_converted", user.id);
  done(contractId);
});

export const saveBillingProfileAction = action(async function saveBillingProfileAction(tenantId: string, input: unknown, contractId?: string) {
  const user = await requirePermission("billing.manage");
  await saveBillingProfile(id.parse(tenantId), input, user.id);
  done(contractId);
});

export const issueInvoiceAction = action(async function issueInvoiceAction(invoiceId: string) {
  const user = await requirePermission("billing.manage");
  const number = await issueInvoice(id.parse(invoiceId), user.id);
  done();
  return number;
});

export const markPaidAction = action(async function markPaidAction(invoiceId: string, reference: string, paidOn: string) {
  const user = await requirePermission("billing.manage");
  await markPaid(id.parse(invoiceId), { reference: z.string().max(120).parse(reference ?? ""), paidAt: date.parse(paidOn) }, user.id);
  done();
});

export const voidInvoiceAction = action(async function voidInvoiceAction(invoiceId: string, reason: string) {
  const user = await requirePermission("billing.manage");
  const r = await voidInvoice(id.parse(invoiceId), z.string().max(500).parse(reason ?? ""), user.id);
  done();
  return r;
});

export const draftDueInvoicesAction = action(async function draftDueInvoicesAction() {
  await requirePermission("billing.manage");
  const n = await generateInvoices();
  done();
  return n;
});

export const saveBillingSettingsAction = action(async function saveBillingSettingsAction(input: unknown) {
  const user = await requirePermission("billing.manage");
  const value = billingSchema.parse(input);
  await setSetting("billing", value, user.id);
  await logAction({ actorId: user.id, action: "settings.billing_changed", detail: { ...value, contractTerms: `${value.contractTerms.length} characters` } });
  done();
});

