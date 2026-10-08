import { randomBytes } from "node:crypto";
import bcrypt from "bcryptjs";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import type { AiTier, OrganizationStatus, ServiceType, InvoiceStatus } from "@prisma/client";

// Admin-provisioned tenant onboarding — there is no public signup. The
// platform owner creates an Organization and its first ORG_ADMIN user in
// one step, after a sales conversation, and hands the generated temp
// password to the customer out of band.

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function generateTempPassword(): string {
  return randomBytes(9).toString("base64url");
}

export interface CreateOrganizationInput {
  name: string;
  aiTier: AiTier;
  orgAdminEmail: string;
  orgAdminName: string;
}

export async function createOrganization(input: CreateOrganizationInput, actorId?: string) {
  const baseSlug = slugify(input.name) || "org";
  let slug = baseSlug;
  let suffix = 1;
  while (await db.organization.findUnique({ where: { slug } })) {
    slug = `${baseSlug}-${++suffix}`;
  }

  const existingUser = await db.user.findUnique({ where: { email: input.orgAdminEmail } });
  if (existingUser) {
    throw new Error(`A user with email ${input.orgAdminEmail} already exists`);
  }

  const tempPassword = generateTempPassword();
  const passwordHash = await bcrypt.hash(tempPassword, 10);

  const org = await db.organization.create({
    data: {
      name: input.name,
      slug,
      aiTier: input.aiTier,
      status: "TRIAL",
      users: {
        create: {
          email: input.orgAdminEmail,
          name: input.orgAdminName,
          role: "ORG_ADMIN",
          passwordHash,
        },
      },
    },
    include: { users: true },
  });

  await logAction({
    actorId,
    organizationId: org.id,
    action: "billing.organization_created",
    detail: { organizationId: org.id, name: org.name, orgAdminEmail: input.orgAdminEmail },
  });

  return { organization: org, tempPassword };
}

export async function listOrganizations() {
  return db.organization.findMany({
    orderBy: { createdAt: "desc" },
    include: { _count: { select: { users: true, cases: true, subscriptions: true } } },
  });
}

export async function getOrganizationDetail(id: string) {
  return db.organization.findUnique({
    where: { id },
    include: {
      users: { orderBy: { createdAt: "asc" } },
      subscriptions: { include: { plan: true }, orderBy: { startedAt: "desc" } },
      invoices: { orderBy: { issueDate: "desc" } },
      pentestRequests: { orderBy: { createdAt: "desc" } },
      integrations: { orderBy: { createdAt: "desc" } },
      _count: { select: { cases: true, agents: true } },
    },
  });
}

export async function updateOrganization(
  id: string,
  data: { aiTier?: AiTier; status?: OrganizationStatus; selfHostedOllamaUrl?: string | null },
  actorId?: string,
) {
  const org = await db.organization.update({ where: { id }, data });
  await logAction({
    actorId,
    organizationId: id,
    action: "billing.organization_updated",
    detail: data,
  });
  return org;
}

// --- Plan catalog ---------------------------------------------------------

export interface PlanInput {
  name: string;
  serviceType: ServiceType;
  aiTier: AiTier;
  priceMonthly: number;
  description?: string;
}

// priceMonthly comes back as a Prisma Decimal, which isn't a plain
// object — Next.js refuses to pass it from a Server Component into a
// Client Component (or across a Server Action boundary) as a prop.
// Nothing here does Decimal-precision arithmetic in JS, so converting to
// a plain number at the read boundary is safe.
export async function listPlans() {
  const plans = await db.plan.findMany({ orderBy: [{ serviceType: "asc" }, { priceMonthly: "asc" }] });
  return plans.map((p) => ({ ...p, priceMonthly: Number(p.priceMonthly) }));
}

export async function createPlan(input: PlanInput) {
  return db.plan.create({
    data: {
      name: input.name,
      serviceType: input.serviceType,
      aiTier: input.aiTier,
      priceMonthly: input.priceMonthly,
      description: input.description,
    },
  });
}

export async function togglePlanActive(id: string, active: boolean) {
  return db.plan.update({ where: { id }, data: { active } });
}

// --- Subscriptions ----------------------------------------------------------

export async function createSubscription(organizationId: string, planId: string, actorId?: string) {
  const periodEnd = new Date();
  periodEnd.setMonth(periodEnd.getMonth() + 1);

  const subscription = await db.subscription.create({
    data: { organizationId, planId, status: "ACTIVE", currentPeriodEnd: periodEnd },
    include: { plan: true },
  });

  await logAction({
    actorId,
    organizationId,
    action: "billing.subscription_created",
    detail: { subscriptionId: subscription.id, planId },
  });

  return subscription;
}

// --- Invoices ---------------------------------------------------------------

export interface InvoiceLineInput {
  description: string;
  quantity: number;
  unitPrice: number;
  subscriptionId?: string;
}

async function nextInvoiceNumber(): Promise<string> {
  const count = await db.invoice.count();
  const year = new Date().getFullYear();
  return `INV-${year}-${String(count + 1).padStart(5, "0")}`;
}

export async function createInvoice(
  organizationId: string,
  lines: InvoiceLineInput[],
  dueInDays = 14,
  actorId?: string,
) {
  const totalAmount = lines.reduce((sum, l) => sum + l.quantity * l.unitPrice, 0);
  const dueDate = new Date();
  dueDate.setDate(dueDate.getDate() + dueInDays);

  const invoice = await db.invoice.create({
    data: {
      organizationId,
      number: await nextInvoiceNumber(),
      dueDate,
      status: "SENT",
      totalAmount,
      lineItems: {
        create: lines.map((l) => ({
          description: l.description,
          quantity: l.quantity,
          unitPrice: l.unitPrice,
          amount: l.quantity * l.unitPrice,
          subscriptionId: l.subscriptionId,
        })),
      },
    },
    include: { lineItems: true },
  });

  await logAction({
    actorId,
    organizationId,
    action: "billing.invoice_created",
    detail: { invoiceId: invoice.id, number: invoice.number, totalAmount },
  });

  return invoice;
}

export async function listInvoices(scope: { organizationId?: string } = {}) {
  const invoices = await db.invoice.findMany({
    where: scope,
    include: { organization: { select: { name: true, slug: true } }, lineItems: true },
    orderBy: { issueDate: "desc" },
  });
  // See listPlans()'s comment — same Decimal-to-number serialization fix.
  return invoices.map((inv) => ({
    ...inv,
    totalAmount: Number(inv.totalAmount),
    lineItems: inv.lineItems.map((li) => ({
      ...li,
      unitPrice: Number(li.unitPrice),
      amount: Number(li.amount),
    })),
  }));
}

// No live payment processor is wired up (per the deliberate v1 scope) —
// this is the manual "record that payment arrived" step a real Stripe/etc.
// webhook would call automatically in a later pass.
export async function setInvoiceStatus(
  id: string,
  status: InvoiceStatus,
  scope: { organizationId?: string } = {},
  actorId?: string,
) {
  const invoice = await db.invoice.findFirstOrThrow({ where: { id, ...scope } });
  const updated = await db.invoice.update({
    where: { id: invoice.id },
    data: { status, paidAt: status === "PAID" ? new Date() : invoice.paidAt },
  });

  await logAction({
    actorId,
    organizationId: invoice.organizationId,
    action: "billing.invoice_status_changed",
    detail: { invoiceId: id, status },
  });

  return updated;
}
