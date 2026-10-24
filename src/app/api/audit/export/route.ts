import { db } from "@/lib/db";
import { currentUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { logAction } from "@/lib/audit";

// Full chain export, in chain order, with every field needed to re-verify
// the hashes offline (see lib/audit.ts computeEntryHash).
export async function GET() {
  const user = await currentUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (!can(user, "audit.export")) return new Response("Forbidden", { status: 403 });

  const logs = await db.auditLog.findMany({
    orderBy: { seq: "asc" },
    select: {
      seq: true,
      id: true,
      createdAt: true,
      actorId: true,
      caseId: true,
      action: true,
      detail: true,
      prevHash: true,
      currentHash: true,
    },
  });

  await logAction({ actorId: user.id, action: "audit.exported", detail: { entries: logs.length } });
  return new Response(JSON.stringify({ exportedAt: new Date().toISOString(), entries: logs }, null, 2), {
    headers: {
      "content-type": "application/json",
      "content-disposition": `attachment; filename="helios-audit-${new Date().toISOString().slice(0, 10)}.json"`,
    },
  });
}
