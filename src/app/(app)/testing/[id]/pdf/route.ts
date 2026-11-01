import { createElement } from "react";

import { db } from "@/lib/db";
import { currentUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { logAction } from "@/lib/audit";
import { getSetting } from "@/lib/settings";
import { pdfResponse } from "@/lib/pdf/kit";
import { SecurityTestPdf } from "@/lib/testing/report-pdf";

// The report of one security test. Another client's tests look missing.
export async function GET(_request: Request, ctx: RouteContext<"/testing/[id]/pdf">) {
  const { id } = await ctx.params;
  const user = await currentUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (!can(user, "testing.view")) return new Response("Not found", { status: 404 });
  const test = await db.securityTest.findUnique({ where: { id }, include: { tenant: { select: { name: true } } } });
  if (!test || (user.isClient && user.tenantId !== test.tenantId)) return new Response("Not found", { status: 404 });
  const company = await getSetting("company.profile");
  await logAction({ actorId: user.id, action: "testing.report_exported", detail: { testId: id } });
  return pdfResponse(createElement(SecurityTestPdf, { test, tenantName: test.tenant.name, company }), `security-test-${id}.pdf`);
}
