import { createElement } from "react";

import { db } from "@/lib/db";
import { currentUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { logAction } from "@/lib/audit";
import { getSetting } from "@/lib/settings";
import { quoteConfigSchema, type QuoteResult } from "@/lib/pricing/calculator";
import { pdfResponse } from "@/lib/pdf/kit";
import { QuotePdf } from "@/lib/pdf/quote";

export async function GET(_request: Request, ctx: RouteContext<"/pricing/quotes/[id]/pdf">) {
  const { id } = await ctx.params;
  const user = await currentUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (!can(user, "pricing.view")) return new Response("Forbidden", { status: 403 });

  const quote = await db.quote.findUnique({ where: { id }, include: { createdBy: { select: { name: true, email: true } } } });
  if (!quote) return new Response("Not found", { status: 404 });
  const company = await getSetting("company.profile");
  const doc = createElement(QuotePdf, {
    quote: { reference: quote.reference, clientName: quote.clientName, currency: quote.currency, validUntil: quote.validUntil, createdAt: quote.createdAt, preparedBy: quote.createdBy?.name ?? quote.createdBy?.email ?? null },
    cfg: quoteConfigSchema.parse(quote.config),
    r: quote.totals as unknown as QuoteResult,
    company,
  });
  await logAction({ actorId: user.id, action: "quote.exported", detail: { quoteId: quote.id, reference: quote.reference } });
  return pdfResponse(doc, `${quote.reference}.pdf`);
}
