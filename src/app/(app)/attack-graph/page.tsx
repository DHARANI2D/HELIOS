import Link from "next/link";
import { GitMerge, Link2, Network } from "lucide-react";

import { pageGuard } from "@/lib/session";
import { caseScope } from "@/lib/access";
import { loadAttackGraph } from "@/lib/cases/attack-graph";
import { getTactic } from "@/lib/mitre/catalog";
import { formatDateTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { StatTile } from "@/components/dashboard/stat-tile";
import { SeverityBadge } from "@/components/shared/case-badges";
import { AttackGraphView, ENTITY_LABEL } from "@/components/cases/attack-graph-view";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const WINDOWS = [7, 30, 90];

async function load(user: Awaited<ReturnType<typeof pageGuard>>, days: number) {
  const since = new Date(Date.now() - days * 86_400_000);
  return loadAttackGraph(await caseScope(user), since);
}

export default async function AttackGraphPage({ searchParams }: PageProps<"/attack-graph">) {
  const user = await pageGuard("cases.view");
  const sp = await searchParams;
  const days = WINDOWS.includes(Number(sp.days)) ? Number(sp.days) : 30;
  const graph = await load(user, days);
  const caseById = new Map(graph.cases.map((c) => [c.id, c]));

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <p className="max-w-2xl text-sm text-muted-foreground">
          Cases joined by the hosts, accounts, addresses and indicators they share. When the cases on one entity together reach more ATT&amp;CK tactics than any of them alone, that&apos;s an attack chain worth reading as one incident.
        </p>
        <nav aria-label="Period" className="flex rounded-md border p-0.5">
          {WINDOWS.map((d) => (
            <Link key={d} href={`/attack-graph?days=${d}`} aria-current={days === d ? "page" : undefined} className={cn("rounded px-2.5 py-1 text-xs font-medium text-muted-foreground hover:text-foreground", days === d && "bg-muted text-foreground")}>
              {d} days
            </Link>
          ))}
        </nav>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatTile label="Linked cases" value={graph.cases.length} icon={Link2} hint={graph.truncated ? "From the newest 300 cases in the period" : undefined} />
        <StatTile label="Shared entities" value={graph.entities.length} icon={Network} />
        <StatTile label="Attack chains" value={graph.chains.length} icon={GitMerge} tone={graph.chains.length ? "warning" : "default"} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Attack chains</CardTitle>
          <CardDescription>Cases on one entity that together reach more tactics than any of them alone — ordered by worst severity, then breadth.</CardDescription>
        </CardHeader>
        <CardContent>
          {graph.chains.length === 0 ? (
            <p className="text-sm text-muted-foreground">No entity ties together cases across different tactics in this period.</p>
          ) : (
            <ul className="divide-y">
              {graph.chains.slice(0, 20).map((chain) => (
                <li key={chain.entity.key} className="flex flex-col gap-2 py-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={chain.severity} />
                    <span className="text-xs text-muted-foreground">{ENTITY_LABEL[chain.entity.type]}</span>
                    <span className="font-mono text-sm break-all">{chain.entity.value}</span>
                    {chain.entity.malicious && <Badge variant="destructive">known malicious</Badge>}
                    <span className="ml-auto text-xs text-muted-foreground">{chain.caseIds.length} cases · {formatDateTime(chain.first)} → {formatDateTime(chain.last)}</span>
                  </div>
                  <ol className="flex flex-wrap items-center gap-1 text-xs" aria-label="Tactics in kill-chain order">
                    {chain.tactics.map((id, i) => (
                      <li key={id} className="flex items-center gap-1">
                        {i > 0 && <span className="text-muted-foreground" aria-hidden>→</span>}
                        <Badge variant="outline">{getTactic(id)?.name ?? id}</Badge>
                      </li>
                    ))}
                  </ol>
                  <ul className="grid gap-0.5 text-xs sm:grid-cols-2">
                    {chain.caseIds.map((id) => caseById.get(id)).filter((c) => !!c).map((c) => (
                      <li key={c!.id} className="truncate"><Link href={`/cases/${c!.id}`} className="hover:underline">{c!.title}</Link></li>
                    ))}
                  </ul>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Graph</CardTitle>
          <CardDescription>Only entities shared by two or more cases are drawn; generic accounts such as SYSTEM and indicators seen in more than 50 cases are left out.</CardDescription>
        </CardHeader>
        <CardContent>
          {graph.entities.length === 0 ? (
            <p className="text-sm text-muted-foreground">No two cases in this period share a host, account, address or indicator.</p>
          ) : (
            <AttackGraphView
              cases={graph.cases.map((c) => ({ id: c.id, title: c.title, severity: c.severity, createdAt: c.createdAt.toISOString(), tenantName: c.tenantName }))}
              entities={graph.entities}
            />
          )}
        </CardContent>
      </Card>

      {graph.entities.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Shared entities</CardTitle>
            <CardDescription>The graph&apos;s links as a table.</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader><TableRow><TableHead>Entity</TableHead><TableHead>Type</TableHead><TableHead className="text-right">Cases</TableHead></TableRow></TableHeader>
              <TableBody>
                {[...graph.entities].sort((a, b) => b.caseIds.length - a.caseIds.length).map((e) => (
                  <TableRow key={e.key}>
                    <TableCell className="max-w-md font-mono text-xs break-all">{e.value}{e.malicious && <Badge variant="destructive" className="ml-2">malicious</Badge>}</TableCell>
                    <TableCell className="text-xs">{ENTITY_LABEL[e.type]}</TableCell>
                    <TableCell className="text-right tabular">{e.caseIds.length}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
