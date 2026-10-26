import { db } from "@/lib/db";
import { currentUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { canAccessCase } from "@/lib/access";
import { logAction } from "@/lib/audit";
import { renderNoticePdf } from "@/lib/compliance/service";

// One regulatory notice as the document that is filed. Out-of-scope cases
// look missing, as on the case page.
export async function GET(_request: Request, ctx: RouteContext<"/cases/[id]/notices/[noticeId]/pdf">) {
  const { id, noticeId } = await ctx.params;
  const user = await currentUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (!can(user, "compliance.view") || !(await canAccessCase(user, id))) return new Response("Not found", { status: 404 });
  const notice = await db.regulatoryNotice.findFirst({ where: { id: noticeId, caseId: id }, select: { id: true, kind: true, sequence: true } });
  if (!notice) return new Response("Not found", { status: 404 });

  const pdf = await renderNoticePdf(notice.id);
  await logAction({ actorId: user.id, caseId: id, action: "compliance.notice_exported", detail: { noticeId: notice.id, kind: notice.kind } });
  const name = `${notice.kind.toLowerCase().replace("_", "-")}-${id}${notice.sequence > 1 ? `-update-${notice.sequence - 1}` : ""}.pdf`;
  return new Response(new Uint8Array(pdf), { headers: { "content-type": "application/pdf", "content-disposition": `attachment; filename="${name}"`, "cache-control": "private, no-store" } });
}
