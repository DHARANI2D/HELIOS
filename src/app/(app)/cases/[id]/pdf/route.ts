import { createElement } from "react";

import { currentUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { canAccessCase } from "@/lib/access";
import { logAction } from "@/lib/audit";
import { getSetting } from "@/lib/settings";
import { pdfResponse } from "@/lib/pdf/kit";
import { CaseReportPdf, loadCaseReport } from "@/lib/pdf/case-report";

// Incident report for one case: investigation and forensics results
// included. Out-of-scope cases look missing, as on the case page.
export async function GET(_request: Request, ctx: RouteContext<"/cases/[id]/pdf">) {
  const { id } = await ctx.params;
  const user = await currentUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (!can(user, "cases.view") || !(await canAccessCase(user, id))) return new Response("Not found", { status: 404 });

  const [report, company] = await Promise.all([loadCaseReport(id, user.isClient ? "client" : "staff"), getSetting("company.profile")]);
  await logAction({ actorId: user.id, caseId: id, action: "case.report_exported", detail: { audience: user.isClient ? "client" : "staff" } });
  return pdfResponse(createElement(CaseReportPdf, { report, company }), `incident-report-${id}.pdf`);
}
