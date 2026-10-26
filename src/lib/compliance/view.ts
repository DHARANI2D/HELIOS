import type { RegulatoryNotice } from "@prisma/client";

import { db } from "@/lib/db";
import { can } from "@/lib/rbac";
import type { SessionUser } from "@/lib/session";
import { mailStatus } from "@/lib/mail";
import { activeRulebook } from "@/lib/rulebook/service";
import { CERT_IN_CATEGORIES, certInLabel } from "@/lib/compliance/cert-in";
import { dpdpInForce } from "@/lib/compliance/dpdp";
import { NOTICE_DEADLINE, NOTICE_LABEL, NOTICE_RECIPIENT, missingFields } from "@/lib/compliance/notices";
import { classifyCase } from "@/lib/compliance/service";
import type { CaseNoticesProps, NoticeView } from "@/components/compliance/case-notices";

// What the case page's regulatory card shows a given user.

export function noticeView(n: RegulatoryNotice, latest: boolean): NoticeView {
  const content = (n.content ?? {}) as Record<string, unknown>;
  return {
    id: n.id,
    kind: n.kind,
    label: NOTICE_LABEL[n.kind],
    recipient: NOTICE_RECIPIENT[n.kind],
    deadline: n.sequence > 1 ? "as the investigation goes" : NOTICE_DEADLINE[n.kind],
    sequence: n.sequence,
    status: n.status,
    clockStartAt: n.clockStartAt.toISOString(),
    dueAt: n.dueAt?.toISOString() ?? null,
    categories: n.categories,
    content,
    missing: missingFields(n.kind, content),
    proposedBy: n.proposedBy,
    approvedByName: n.approvedByName,
    approvedVia: n.approvedVia,
    approvedAt: n.approvedAt?.toISOString() ?? null,
    submittedAt: n.submittedAt?.toISOString() ?? null,
    submittedVia: n.submittedVia,
    reference: n.reference,
    recipientsCount: n.recipientsCount,
    notRequiredReason: n.notRequiredReason,
    latest,
  };
}

export async function caseNoticesProps(kase: { id: string; tenantId: string | null; createdAt: Date }, user: SessionUser, now = new Date()): Promise<CaseNoticesProps> {
  const [notices, book, mail, matches] = await Promise.all([
    db.regulatoryNotice.findMany({ where: { caseId: kase.id }, orderBy: [{ kind: "asc" }, { sequence: "asc" }] }),
    kase.tenantId ? activeRulebook(kase.tenantId) : Promise.resolve(null),
    user.isClient ? Promise.resolve({ configured: false }) : mailStatus(),
    kase.tenantId && !user.isClient ? classifyCase(kase.id) : Promise.resolve([]),
  ]);
  const ob = book?.body.obligations;
  const lastCertIn = Math.max(0, ...notices.filter((n) => n.kind === "CERT_IN").map((n) => n.sequence));
  return {
    caseId: kase.id,
    now: now.toISOString(),
    createdAt: kase.createdAt.toISOString(),
    obligations: kase.tenantId ? { certIn: !!ob?.regulatedEntity, dpdp: !!ob?.dpdpFiduciary, minSeverity: ob?.certInMinSeverity ?? "HIGH", withoutDelayHours: ob?.dpdpWithoutDelayHours ?? 24 } : null,
    matches: matches.map((m) => ({ code: m.code, label: certInLabel(m.code), reasons: m.reasons })),
    categories: CERT_IN_CATEGORIES.map((c) => ({ code: c.code, label: c.label })),
    notices: notices.map((n) => noticeView(n, n.kind !== "CERT_IN" || n.sequence === lastCertIn)),
    mail,
    perms: { prepare: can(user, "compliance.prepare"), approve: can(user, "compliance.approve"), isClient: user.isClient },
    dpdpInForce: dpdpInForce(now),
  };
}
