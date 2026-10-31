import Link from "next/link";
import { CheckCircle2, GitPullRequestArrow } from "lucide-react";

import { db } from "@/lib/db";
import { dbFor, type ScopedDb } from "@/lib/tenant-db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { changeView } from "@/lib/changes/view";
import { ChangeCard } from "@/components/changes/change-card";
import { EmptyState } from "@/components/shared/empty-state";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export const metadata = { title: "Rule changes" };

// Every change to the rules containment runs under, waiting or decided:
// rulebook versions, allowlist entries, AI autonomy and consent, and the
// platform's AI limits. A client's changes take effect once the client and
// HELIOS have both approved them; platform changes once a second HELIOS
// approver has. Client users see their own organisation's only.
export default async function ChangesPage({ searchParams }: PageProps<"/changes">) {
  const user = await pageGuard("rulebook.view");
  const sp = await searchParams;
  const scope = typeof sp.scope === "string" ? sp.scope : "all";
  const client = user.isClient;
  const seesPlatform = !client && can(user, "ai.configure");
  const where = client ? { tenantId: user.tenantId ?? "__none__" } : scope === "platform" ? { tenantId: null } : scope === "clients" ? { tenantId: { not: null } } : seesPlatform ? {} : { tenantId: { not: null } };
  const q: ScopedDb = client ? dbFor(user) : db;
  const [pending, history] = await Promise.all([
    (q as typeof db).ruleChange.findMany({ where: { ...where, status: "PENDING" }, include: { tenant: { select: { name: true } } }, orderBy: { createdAt: "asc" }, take: 200 }),
    (q as typeof db).ruleChange.findMany({ where: { ...where, status: { not: "PENDING" } }, include: { tenant: { select: { name: true } } }, orderBy: { updatedAt: "desc" }, take: 50 }),
  ]);
  const me = { id: user.id, role: user.role, isClient: user.isClient, tenantId: user.tenantId, active: true };
  const views = pending.map((c) => changeView(c, me));
  const mine = views.filter((v) => v.can.client || v.can.helios).length;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="flex items-center gap-2 text-sm text-muted-foreground"><GitPullRequestArrow className="size-4" /> {pending.length} waiting · {mine} for you</p>
          <h2 className="text-xl font-semibold tracking-tight">Rule changes</h2>
          <p className="max-w-3xl text-sm text-muted-foreground">
            The AI contains threats only within rules people set. {client ? "A change to your rules" : "A change to a client's rules"} takes effect once the client and HELIOS have both approved it; a change to the platform&apos;s AI limits, once a second HELIOS approver has. Nobody approves their own request for HELIOS, and no AI can ask for or approve a change. Stopping the AI (the kill switch, lowering its autonomy or consent) never waits.
          </p>
        </div>
        {!client && (
          <div className="flex gap-1">
            {(seesPlatform ? ["all", "clients", "platform"] : ["all"]).map((s) => (
              <Button key={s} size="sm" variant={scope === s ? "default" : "outline"} asChild>
                <Link href={s === "all" ? "/changes" : `/changes?scope=${s}`}>{s === "all" ? "All" : s === "clients" ? "Clients" : "Platform"}</Link>
              </Button>
            ))}
          </div>
        )}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Waiting for approval</CardTitle>
          <CardDescription>Nothing here is in effect yet: the rules in force keep deciding until every approval a change needs is in.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {views.length === 0 ? (
            <EmptyState icon={CheckCircle2} title="No rule changes waiting" description="Rulebook versions, allowlist entries, autonomy promotions, consent and AI limit changes show up here until they're approved." />
          ) : (
            views.map((v) => <ChangeCard key={v.id} change={v} />)
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Decided</CardTitle>
          <CardDescription>The last 50: put in effect, turned down, withdrawn, or lapsed because what they changed moved on first. Each is in the audit chain with its fingerprint.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {history.length === 0 ? <p className="text-sm text-muted-foreground">None yet.</p> : history.map((c) => <ChangeCard key={c.id} change={changeView(c, me)} compact />)}
        </CardContent>
      </Card>
    </div>
  );
}
