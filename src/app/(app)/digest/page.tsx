import Link from "next/link";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { forbidden } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

// The daily digests someone can read: a client's own, or all for staff.
export default async function DigestsPage() {
  const user = await pageGuard();
  if (!(user.isClient ? can(user, "reports.view") : can(user, "operations.view"))) forbidden();
  const runs = await db.digestRun.findMany({ where: { recipients: { gt: 0 }, ...(user.isClient ? { tenantId: user.tenantId } : {}) }, orderBy: { createdAt: "desc" }, take: 60 });
  const names = new Map((await db.tenant.findMany({ where: { id: { in: runs.map((r) => r.tenantId).filter((x): x is string => !!x) } }, select: { id: true, name: true } })).map((t) => [t.id, t.name]));
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Daily digests</CardTitle>
        <CardDescription>What HELIOS did on its own each day, what was waiting on someone, and the deadlines coming up.</CardDescription>
      </CardHeader>
      <CardContent>
        {runs.length ? (
          <ul className="divide-y text-sm">
            {runs.map((r) => (
              <li key={r.id} className="py-2">
                <Link href={`/digest/${r.id}`} className="hover:underline">{r.day.toISOString().slice(0, 10)} · {r.tenantId ? names.get(r.tenantId) ?? "Client" : "All clients (SOC)"}</Link>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">No digest yet.</p>
        )}
      </CardContent>
    </Card>
  );
}
