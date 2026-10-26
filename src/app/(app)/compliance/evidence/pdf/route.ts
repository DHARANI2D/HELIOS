import { createElement } from "react";

import { db } from "@/lib/db";
import { currentUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { selectedTenantId } from "@/lib/access";
import { logAction } from "@/lib/audit";
import { getSetting } from "@/lib/settings";
import { evidenceMap } from "@/lib/compliance/iso27001";
import { pdfResponse } from "@/lib/pdf/kit";
import { EvidencePdf } from "@/lib/pdf/evidence";

// The Compliance page's evidence map as a PDF, for the same scope.
export async function GET(request: Request) {
  const user = await currentUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (!can(user, "compliance.view")) return new Response("Forbidden", { status: 403 });

  const asked = Number(new URL(request.url).searchParams.get("days"));
  const days = [30, 90, 365].includes(asked) ? asked : 90;
  const now = new Date();
  const selected = await selectedTenantId(user);
  const [controls, company, tenant] = await Promise.all([
    evidenceMap(selected, days, now),
    getSetting("company.profile"),
    selected ? db.tenant.findUnique({ where: { id: selected }, select: { name: true, slug: true } }) : Promise.resolve(null),
  ]);
  await logAction({ actorId: user.id, action: "compliance.evidence_exported", detail: { days, tenant: tenant?.slug ?? null } });
  return pdfResponse(createElement(EvidencePdf, { controls, company, scope: tenant?.name ?? "All clients", days, now }), `iso27001-evidence-${tenant?.slug ?? "all-clients"}-${days}d.pdf`);
}
