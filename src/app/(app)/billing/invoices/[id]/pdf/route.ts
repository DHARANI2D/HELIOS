import { createElement } from "react";

import { db } from "@/lib/db";
import { currentUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { logAction } from "@/lib/audit";
import { getSetting } from "@/lib/settings";
import { invoiceLinesOf, taxLinesOf } from "@/lib/billing/service";
import { pdfResponse } from "@/lib/pdf/kit";
import { InvoicePdf, type InvoiceDoc } from "@/lib/pdf/invoice";

export async function GET(_request: Request, ctx: RouteContext<"/billing/invoices/[id]/pdf">) {
  const { id } = await ctx.params;
  const user = await currentUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (!can(user, "billing.view")) return new Response("Forbidden", { status: 403 });
  const inv = await db.invoice.findUnique({ where: { id }, include: { contract: { select: { reference: true } } } });
  if (!inv || !inv.number || (user.isClient && inv.tenantId !== user.tenantId)) return new Response("Not found", { status: 404 });
  const [company, billing] = await Promise.all([getSetting("company.profile"), getSetting("billing")]);
  const doc = createElement(InvoicePdf, {
    inv: {
      number: inv.number,
      issuedAt: inv.issuedAt!,
      dueAt: inv.dueAt,
      periodFrom: inv.periodFrom,
      periodTo: inv.periodTo,
      currency: inv.currency,
      lines: invoiceLinesOf(inv.lines),
      subtotal: inv.subtotal,
      taxMode: inv.taxMode,
      taxLines: taxLinesOf(inv.taxLines),
      total: inv.total,
      sac: inv.sac,
      status: inv.status,
      voidReason: inv.voidReason,
      contractReference: inv.contract?.reference ?? null,
      supplier: inv.supplier as unknown as InvoiceDoc["supplier"],
      recipient: inv.recipient as unknown as InvoiceDoc["recipient"],
      paymentDetails: billing.paymentDetails,
    },
    company,
  });
  await logAction({ actorId: user.id, action: "invoice.exported", detail: { invoiceId: id, number: inv.number } });
  return pdfResponse(doc, `${inv.number.replaceAll("/", "-")}.pdf`);
}
