import Link from "next/link";
import { ShieldCheck } from "lucide-react";

import { db } from "@/lib/db";
import { dbFor } from "@/lib/tenant-db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { formatDateTime } from "@/lib/format";
import { CHECKS } from "@/lib/testing/exposure";
import { severityCounts } from "@/lib/testing/findings";
import { findingsOf } from "@/lib/testing/service";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/shared/empty-state";
import { RequestTestForm } from "@/components/testing/test-controls";
import { TestStatusBadge } from "@/components/testing/status-badge";

// Security tests of clients' internet-facing assets, on request and under
// written authorisation from both the client and HELIOS.
export default async function TestingPage() {
  const user = await pageGuard("testing.view");
  const [tests, tenants] = await Promise.all([
    dbFor(user).securityTest.findMany({ where: user.isClient ? { tenantId: user.tenantId ?? "__none__" } : {}, include: { tenant: { select: { name: true } } }, orderBy: { createdAt: "desc" }, take: 200 }),
    user.isClient ? Promise.resolve([]) : db.tenant.findMany({ select: { id: true, name: true }, orderBy: { name: "asc" } }),
  ]);
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="flex items-center gap-2 text-sm text-muted-foreground"><ShieldCheck className="size-4" /> Authorised by {user.isClient ? "you" : "the client"} and HELIOS, on assets {user.isClient ? "you" : "the client"} proved {user.isClient ? "you" : "it"} control{user.isClient ? "" : "s"}</p>
          <h2 className="text-xl font-semibold tracking-tight">Security testing</h2>
        </div>
        {can(user, "testing.request") && <RequestTestForm tenants={tenants} isClient={user.isClient} checks={{ ...CHECKS }} />}
      </div>
      <Card>
        <CardContent className="flex flex-col divide-y">
          {tests.length === 0 && <EmptyState icon={ShieldCheck} title="No security tests yet" description="Ask for one: HELIOS checks what your internet-facing assets expose (services, TLS, web headers, email spoofing protection) and reports what to fix. Results from Nessus, Greenbone, ZAP or Nuclei can be added to the same report." />}
          {tests.map((t) => {
            const c = severityCounts(findingsOf(t));
            return (
              <Link key={t.id} href={`/testing/${t.id}`} className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0 hover:opacity-80">
                <div className="min-w-0 flex-1">
                  <p className="flex items-center gap-2 text-sm font-medium">{user.isClient ? t.title : `${t.tenant.name} · ${t.title}`} <TestStatusBadge status={t.status} /></p>
                  <p className="text-xs text-muted-foreground">
                    {formatDateTime(t.windowStart)} → {formatDateTime(t.windowEnd)} · asked by {t.requestedByName} · {t.runs} run(s)
                  </p>
                </div>
                <div className="flex gap-1">
                  {c.critical > 0 && <Badge variant="destructive">{c.critical} critical</Badge>}
                  {c.high > 0 && <Badge variant="warning">{c.high} high</Badge>}
                  {c.medium > 0 && <Badge variant="outline">{c.medium} medium</Badge>}
                </div>
              </Link>
            );
          })}
        </CardContent>
      </Card>
    </div>
  );
}
