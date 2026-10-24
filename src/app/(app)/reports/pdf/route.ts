import { createElement } from "react";

import { db } from "@/lib/db";
import { currentUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { caseScope, selectedTenantId } from "@/lib/access";
import { logAction } from "@/lib/audit";
import { getSetting } from "@/lib/settings";
import { loadServiceReport, parseRange } from "@/lib/reports";
import { pdfResponse } from "@/lib/pdf/kit";
import { ServiceReportPdf } from "@/lib/pdf/service-report";

// The Reports page as a PDF, for the same scope the viewer sees there.
export async function GET(request: Request) {
  const user = await currentUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (!can(user, "reports.view")) return new Response("Forbidden", { status: 403 });

  const url = new URL(request.url);
  const range = parseRange({ range: url.searchParams.get("range") ?? undefined, month: url.searchParams.get("month") ?? undefined });
  const [scope, selected, company] = await Promise.all([caseScope(user), selectedTenantId(user), getSetting("company.profile")]);
  const tenant = selected ? await db.tenant.findUnique({ where: { id: selected }, select: { name: true, slug: true } }) : null;
  const report = await loadServiceReport(scope, range);
  const scopeLabel = tenant?.name ?? (user.isClient ? user.tenantName ?? "your organization" : "all clients");

  await logAction({ actorId: user.id, action: "report.exported", detail: { range: range.key, tenant: tenant?.slug ?? null } });
  return pdfResponse(
    createElement(ServiceReportPdf, { report, company, scope: scopeLabel, internal: !user.isClient }),
    `service-report-${tenant?.slug ?? "all-clients"}-${range.key}.pdf`,
  );
}
