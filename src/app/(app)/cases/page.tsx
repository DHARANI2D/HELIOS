import Link from "next/link";
import { Activity, Inbox, Radar, ShieldAlert, Workflow } from "lucide-react";
import type { CaseSeverity, CaseSource } from "@prisma/client";

import { db } from "@/lib/db";
import { caseWhere } from "@/lib/cases/service";
import { CASE_SOURCES, CASE_SOURCE_LABEL } from "@/lib/cases/labels";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";
import { formatRelative } from "@/lib/format";
import { StatTile } from "@/components/dashboard/stat-tile";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge, SourceBadge, StatusBadge } from "@/components/shared/case-badges";
import { EmptyState } from "@/components/shared/empty-state";
import { Pagination, parsePage } from "@/components/shared/pagination";
import { SimulationPanel } from "@/components/cases/simulation-panel";
import { IngestPanel } from "@/components/cases/ingest-panel";

const PAGE_SIZE = 25;

function one(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

async function getStreamStats() {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const [openCount, detections24h, events24h, awaiting] = await Promise.all([
    db.case.count({ where: caseWhere({ status: "open" }) }),
    db.detection.count({ where: { createdAt: { gte: since } } }),
    db.securityEvent.count({ where: { ingestedAt: { gte: since } } }),
    db.case.count({ where: { status: "AWAITING_APPROVAL" } }),
  ]);
  return { openCount, detections24h, events24h, awaiting };
}

export default async function CasesPage({ searchParams }: PageProps<"/cases">) {
  const sp = await searchParams;
  const page = parsePage(sp.page);
  const source = CASE_SOURCES.includes(one(sp.source) as CaseSource) ? (one(sp.source) as CaseSource) : undefined;
  const severity = SEVERITY_ORDER.includes(one(sp.severity) as CaseSeverity) ? (one(sp.severity) as CaseSeverity) : undefined;
  const statusParam = one(sp.status);
  const status = statusParam === "closed" || statusParam === "all" ? statusParam : "open";
  const q = one(sp.q)?.trim() || undefined;
  const technique = /^T\d{4}(\.\d{3})?$/.test(one(sp.technique) ?? "") ? one(sp.technique) : undefined;

  const where = caseWhere({ sourceType: source, severity, status, q, technique });

  const [cases, total, { openCount, detections24h, events24h, awaiting }] = await Promise.all([
    db.case.findMany({
      where,
      orderBy: [{ createdAt: "desc" }],
      skip: (page - 1) * PAGE_SIZE,
      take: PAGE_SIZE,
      include: {
        assignedTo: { select: { name: true, email: true } },
        _count: { select: { detections: true } },
      },
    }),
    db.case.count({ where }),
    getStreamStats(),
  ]);

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="Open cases" value={openCount} icon={ShieldAlert} />
        <StatTile label="Detections (24h)" value={detections24h} icon={Radar} />
        <StatTile label="Events ingested (24h)" value={events24h} icon={Activity} />
        <StatTile label="Awaiting approval" value={awaiting} icon={Workflow} tone={awaiting > 0 ? "warning" : "default"} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <SimulationPanel />
        <IngestPanel />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Unified case stream</CardTitle>
          <CardDescription>Every case from every module — SIEM detections, investigations, email forensics, and agent governance.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <form className="flex flex-wrap items-end gap-2" action="/cases">
            <Input name="q" defaultValue={q} placeholder="Search title, summary, entity…" className="w-64" />
            <NativeSelect name="source" defaultValue={source ?? ""} aria-label="Source">
              <option value="">All sources</option>
              {CASE_SOURCES.map((s) => (
                <option key={s} value={s}>{CASE_SOURCE_LABEL[s]}</option>
              ))}
            </NativeSelect>
            <NativeSelect name="severity" defaultValue={severity ?? ""} aria-label="Severity">
              <option value="">Any severity</option>
              {SEVERITY_ORDER.map((s) => (
                <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>
              ))}
            </NativeSelect>
            <NativeSelect name="status" defaultValue={status} aria-label="Status">
              <option value="open">Open</option>
              <option value="closed">Closed</option>
              <option value="all">All</option>
            </NativeSelect>
            {technique && <input type="hidden" name="technique" value={technique} />}
            <Button type="submit" variant="secondary">Filter</Button>
            {technique && (
              <span className="rounded-md border px-2 py-1 font-mono text-xs">technique {technique}</span>
            )}
            {(q || source || severity || technique || status !== "open") && (
              <Button variant="ghost" asChild>
                <Link href="/cases">Reset</Link>
              </Button>
            )}
          </form>

          {cases.length === 0 ? (
            <EmptyState
              icon={Inbox}
              title="No cases match"
              description="Run an attack simulation or ingest telemetry above to generate detections."
            />
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-24">Severity</TableHead>
                    <TableHead>Case</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Detections</TableHead>
                    <TableHead className="text-right">Risk</TableHead>
                    <TableHead>Assignee</TableHead>
                    <TableHead className="text-right">Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {cases.map((c) => (
                    <TableRow key={c.id}>
                      <TableCell><SeverityBadge severity={c.severity} /></TableCell>
                      <TableCell className="max-w-md">
                        <Link href={`/cases/${c.id}`} className="line-clamp-1 font-medium hover:underline">
                          {c.title}
                        </Link>
                        {c.verdict && <span className="text-xs capitalize text-muted-foreground">Verdict: {c.verdict}</span>}
                      </TableCell>
                      <TableCell><SourceBadge source={c.sourceType} /></TableCell>
                      <TableCell><StatusBadge status={c.status} /></TableCell>
                      <TableCell className="text-right tabular-nums">{c._count.detections}</TableCell>
                      <TableCell className="text-right tabular-nums">{c.riskScore != null ? Math.round(c.riskScore) : "—"}</TableCell>
                      <TableCell className="text-xs">{c.assignedTo ? (c.assignedTo.name ?? c.assignedTo.email) : <span className="text-muted-foreground">—</span>}</TableCell>
                      <TableCell className="text-right text-xs text-muted-foreground" title={c.createdAt.toISOString()}>
                        {formatRelative(c.createdAt)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <Pagination
                page={page}
                pageSize={PAGE_SIZE}
                total={total}
                basePath="/cases"
                params={{ q, source, severity, technique, status: status === "open" ? undefined : status }}
              />
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
