import { createElement } from "react";

import { db } from "@/lib/db";
import { currentUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { logAction } from "@/lib/audit";
import { getSetting } from "@/lib/settings";
import { parseCriteria } from "@/lib/billing/service";
import { pdfResponse } from "@/lib/pdf/kit";
import { ContractPdf } from "@/lib/pdf/contract";

export async function GET(_request: Request, ctx: RouteContext<"/billing/contracts/[id]/pdf">) {
  const { id } = await ctx.params;
  const user = await currentUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (!can(user, "billing.view")) return new Response("Forbidden", { status: 403 });
  const c = await db.contract.findUnique({ where: { id }, include: { tenant: { select: { name: true } } } });
  // Out of scope looks like missing.
  if (!c || (user.isClient && c.tenantId !== user.tenantId)) return new Response("Not found", { status: 404 });
  const company = await getSetting("company.profile");
  const doc = createElement(ContractPdf, { c: { ...c, clientName: c.tenant.name, criteria: parseCriteria(c.successCriteria) }, company });
  await logAction({ actorId: user.id, action: "contract.exported", detail: { contractId: id, reference: c.reference } });
  return pdfResponse(doc, `${c.reference}.pdf`);
}
