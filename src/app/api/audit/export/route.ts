import { auth } from "@/lib/auth";
import { db } from "@/lib/db";

// Full chain export, in chain order, with every field needed to re-verify
// the hashes offline (see lib/audit.ts computeEntryHash).
export async function GET() {
  const session = await auth();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });

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

  return new Response(JSON.stringify({ exportedAt: new Date().toISOString(), entries: logs }, null, 2), {
    headers: {
      "content-type": "application/json",
      "content-disposition": `attachment; filename="helios-audit-${new Date().toISOString().slice(0, 10)}.json"`,
    },
  });
}
