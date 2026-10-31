import Link from "next/link";

import type { DigestSummary } from "@/lib/operations/digest";
import { formatDateTime } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const STATUS_LABEL: Record<string, string> = { EXECUTED: "Done", ROLLED_BACK: "Rolled back", IN_PROGRESS: "In progress", FAILED: "Failed" };

export function DigestView({ d }: { d: DigestSummary }) {
  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">What HELIOS did on its own</CardTitle>
          <CardDescription>{formatDateTime(d.from)} to {formatDateTime(d.to)}{d.scope.tenantId ? ` · ${d.scope.name}` : " · every client"}. Each action can be rolled back from its case.</CardDescription>
        </CardHeader>
        <CardContent>
          {d.aiActions.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Case</TableHead>
                  <TableHead>Result</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {d.aiActions.map((a, i) => (
                  <TableRow key={i}>
                    <TableCell className="text-xs tabular">{formatDateTime(a.at)}</TableCell>
                    <TableCell className="text-xs">{a.action} {a.target && <span className="font-mono">{a.target}</span>}{a.level != null && <span className="text-muted-foreground"> · level {a.level}</span>}</TableCell>
                    <TableCell className="max-w-72 whitespace-normal text-xs"><Link href={`/cases/${a.caseId}`} className="hover:underline">{a.caseTitle}</Link></TableCell>
                    <TableCell className="text-xs">{STATUS_LABEL[a.status] ?? a.status}{a.qa && <Badge variant={a.qa === "wrong" ? "destructive" : "success"} className="ml-1">QA: {a.qa}</Badge>}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-sm text-muted-foreground">It took no action on its own.</p>
          )}
          {d.aiActionsTotal > d.aiActions.length && <p className="mt-2 text-xs text-muted-foreground">And {d.aiActionsTotal - d.aiActions.length} more.</p>}
        </CardContent>
      </Card>
      <div className="grid gap-4 sm:grid-cols-2">
        <Card>
          <CardHeader><CardTitle className="text-base">Cases</CardTitle></CardHeader>
          <CardContent className="text-sm">
            <p>{d.opened.total} opened ({d.opened.critical} critical, {d.opened.high} high)</p>
            <p>{d.closed.total} closed: {d.closed.truePositive} true positive, {d.closed.benign} benign, {d.closed.falsePositive} false positive</p>
            <p>{d.pendingApprovals} containment action{d.pendingApprovals === 1 ? "" : "s"} waiting for approval</p>
            {d.quietSources > 0 && <p className="text-warning-ink">{d.quietSources} log source{d.quietSources === 1 ? "" : "s"} gone quiet</p>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-base">Deadlines and checks</CardTitle></CardHeader>
          <CardContent className="flex flex-col gap-1 text-sm">
            {d.notices.length ? d.notices.map((n, i) => (
              <p key={i} className={n.overdue ? "text-destructive" : ""}>{n.overdue ? "Overdue" : "Due"}: {n.kind} on <Link href={`/cases/${n.caseId}#regulatory`} className="hover:underline">{n.caseTitle}</Link>{n.dueAt ? ` (${formatDateTime(n.dueAt)})` : ""}</p>
            )) : <p className="text-muted-foreground">No regulatory deadline in the next day.</p>}
            <p>QA this week: {d.qa.reviewed} reviewed, {d.qa.agree} right, {d.qa.partly} partly, {d.qa.disagree} wrong</p>
            {d.pages && <p>Pages: {d.pages.total} sent, {d.pages.unanswered} unanswered now</p>}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
