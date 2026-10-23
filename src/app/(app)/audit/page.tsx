import Link from "next/link";
import { Download, ScrollText } from "lucide-react";
import type { Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { formatDateTime, shortHash } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { JsonView } from "@/components/shared/json-view";
import { EmptyState } from "@/components/shared/empty-state";
import { Pagination, parsePage } from "@/components/shared/pagination";
import { VerifyChainButton } from "@/components/audit/verify-chain-button";

const PAGE_SIZE = 50;

// Action names are namespaced by module ("governance.scenario_run",
// "playbook.executed", ...), so the prefix doubles as a module filter.
const MODULE_FILTERS = [
  { value: "", label: "All" },
  { value: "case.", label: "Cases" },
  { value: "siem.", label: "Detection" },
  { value: "investigation.", label: "Investigations" },
  { value: "forensics.", label: "Forensics" },
  { value: "governance.", label: "Governance" },
  { value: "playbook.", label: "Playbooks" },
  { value: "intel.", label: "Threat intel" },
];

export default async function AuditPage({ searchParams }: PageProps<"/audit">) {
  const sp = await searchParams;
  const page = parsePage(sp.page);
  const moduleFilter = typeof sp.module === "string" ? sp.module : "";

  const where: Prisma.AuditLogWhereInput = moduleFilter ? { action: { startsWith: moduleFilter } } : {};

  const [logs, total, chainLength] = await Promise.all([
    db.auditLog.findMany({
      where,
      orderBy: { seq: "desc" },
      skip: (page - 1) * PAGE_SIZE,
      take: PAGE_SIZE,
      include: {
        actor: { select: { name: true, email: true } },
        case: { select: { id: true, title: true } },
      },
    }),
    db.auditLog.count({ where }),
    db.auditLog.count(),
  ]);

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-4">
          <div>
            <CardTitle className="text-base">Hash-chained audit trail</CardTitle>
            <CardDescription>
              {chainLength} entries. Each entry stores the SHA-256 of its content plus the previous entry&apos;s hash,
              so editing or deleting any row breaks every hash after it.
            </CardDescription>
          </div>
          <Button variant="outline" size="sm" asChild>
            <a href="/api/audit/export">
              <Download /> Export JSON
            </a>
          </Button>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <VerifyChainButton />
          <div className="flex flex-wrap gap-1.5">
            {MODULE_FILTERS.map((f) => (
              <Link
                key={f.value}
                href={f.value ? `/audit?module=${encodeURIComponent(f.value)}` : "/audit"}
                className={cn(
                  "rounded-md border px-2.5 py-1 text-xs transition-colors hover:bg-accent",
                  moduleFilter === f.value && "border-primary bg-primary text-primary-foreground hover:bg-primary/90",
                )}
              >
                {f.label}
              </Link>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          {logs.length === 0 ? (
            <EmptyState
              icon={ScrollText}
              title="No audit entries yet"
              description="Every write action across HELIOS — case changes, scenario runs, playbook executions — is recorded here."
            />
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-14">#</TableHead>
                    <TableHead className="w-44">Time</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Actor</TableHead>
                    <TableHead>Case</TableHead>
                    <TableHead>Hash</TableHead>
                    <TableHead>Detail</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {logs.map((log) => (
                    <TableRow key={log.id} className="align-top">
                      <TableCell className="tabular-nums text-muted-foreground">{log.seq}</TableCell>
                      <TableCell className="text-xs tabular-nums">{formatDateTime(log.createdAt)}</TableCell>
                      <TableCell className="font-mono text-xs">{log.action}</TableCell>
                      <TableCell className="text-xs">
                        {log.actor ? (log.actor.name ?? log.actor.email) : <span className="text-muted-foreground">system</span>}
                      </TableCell>
                      <TableCell className="max-w-48 text-xs">
                        {log.case ? (
                          <Link href={`/cases/${log.case.id}`} className="line-clamp-1 hover:underline">
                            {log.case.title}
                          </Link>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground" title={log.currentHash}>
                        {shortHash(log.currentHash)}
                      </TableCell>
                      <TableCell className="w-72 text-xs">
                        {log.detail ? (
                          <details>
                            <summary className="cursor-pointer text-muted-foreground hover:text-foreground">View</summary>
                            <JsonView value={log.detail} className="mt-2 w-72" />
                          </details>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <Pagination page={page} pageSize={PAGE_SIZE} total={total} params={{ module: moduleFilter || undefined }} basePath="/audit" />
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
