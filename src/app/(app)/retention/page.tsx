import { Archive, Database, Lock, MapPin } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { formatDateTime } from "@/lib/format";
import { CERT_IN_DAYS, retentionReport } from "@/lib/retention/service";
import { HoldForm, ReleaseHold, RetentionForm } from "@/components/retention/retention-controls";
import { StatTile } from "@/components/dashboard/stat-tile";
import { TestBadge } from "@/components/shared/test-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const bytes = (n: number) => (n < 1024 ? `${n} B` : n < 1024 ** 2 ? `${(n / 1024).toFixed(1)} KB` : n < 1024 ** 3 ? `${(n / 1024 ** 2).toFixed(1)} MB` : `${(n / 1024 ** 3).toFixed(2)} GB`);

// Where each client's logs are, how long they're kept, and what's on hold.
export default async function RetentionPage() {
  const user = await pageGuard("audit.view");
  const canEdit = can(user, "settings.manage");
  const [report, archives] = await Promise.all([
    retentionReport(),
    db.eventArchive.findMany({ where: { deletedAt: null }, orderBy: { day: "desc" }, take: 30, include: { tenant: { select: { name: true } } } }),
  ]);
  const certIn = report.tenants.filter((t) => t.certIn);
  const short = certIn.filter((t) => t.retentionDays < CERT_IN_DAYS);
  const holds = report.tenants.flatMap((t) => t.holds.map((h) => ({ ...h, tenantName: t.name })));

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
        <StatTile label="Events searchable" value={report.tenants.reduce((n, t) => n + t.hotEvents, 0).toLocaleString()} icon={Database} />
        <StatTile label="Events archived" value={report.tenants.reduce((n, t) => n + t.archivedEvents, 0).toLocaleString()} icon={Archive} hint={bytes(report.tenants.reduce((n, t) => n + t.archivedBytes, 0))} />
        <StatTile label="Legal holds in force" value={holds.filter((h) => !h.releasedAt).length} icon={Lock} />
        <StatTile label="Logs in India" value={report.inIndia ? "Yes" : "Not shown"} icon={MapPin} tone={certIn.length && !report.inIndia ? "warning" : "default"} hint={`Database: ${report.database.region ?? "region not declared"}${report.store ? ` · archive: ${report.store.region ?? "region unknown"}` : ""}`} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Where the logs are kept</CardTitle>
          <CardDescription>
            CERT-In&apos;s directions ask for logs of all ICT systems kept for a rolling {CERT_IN_DAYS} days within Indian jurisdiction. HELIOS can only vouch for what it&apos;s told: the archive store&apos;s region, and the database region the operator declares (HELIOS_DATA_REGION).
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2 text-sm sm:grid-cols-2">
          <div className="rounded-md border p-3">
            <p className="text-xs text-muted-foreground">Archive store</p>
            <p className="font-medium">{report.store ? report.store.describe : "Not configured"}</p>
            <p className="text-xs">{report.store ? (report.store.inIndia ? "In an Indian region" : `Region ${report.store.region ?? "unknown"}: not shown to be in India`) : "Set HELIOS_ARCHIVE_S3_BUCKET (and region) or HELIOS_ARCHIVE_DIR. Until then, events stay in the database until their retention ends."}</p>
          </div>
          <div className="rounded-md border p-3">
            <p className="text-xs text-muted-foreground">Database</p>
            <p className="font-medium">{report.database.region ?? "Region not declared"}</p>
            <p className="text-xs">{report.database.inIndia ? "Declared as in India" : "Set HELIOS_DATA_REGION to where the database runs (e.g. ap-south-1)."}</p>
          </div>
          {short.length > 0 && <p className="text-xs text-destructive sm:col-span-2">Below {CERT_IN_DAYS} days for a client CERT-In applies to: {short.map((t) => t.name).join(", ")}.</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Retention by client</CardTitle>
          <CardDescription>Events stay searchable for the first period, then move to the archive one day at a time (compressed and encrypted with the client&apos;s own key), and are deleted when the whole period ends. Events attached to a case are kept with the case.</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Client</TableHead>
                <TableHead>Searchable / kept</TableHead>
                <TableHead>In the database</TableHead>
                <TableHead>Archived</TableHead>
                <TableHead>Oldest kept</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {report.tenants.map((t) => (
                <TableRow key={t.id}>
                  <TableCell className="text-xs font-medium">
                    {t.name}{t.isTest && <TestBadge className="ml-1" />}
                    {t.certIn && <Badge variant="soft" className="ml-1">CERT-In</Badge>}
                  </TableCell>
                  <TableCell>{canEdit ? <RetentionForm tenantId={t.id} hotDays={t.hotDays} retentionDays={t.retentionDays} minDays={t.minDays} /> : <span className="text-xs">{t.hotDays} / {t.retentionDays} days</span>}</TableCell>
                  <TableCell className="text-xs tabular">{t.hotEvents.toLocaleString()} events{t.caseEvents ? ` (${t.caseEvents.toLocaleString()} on cases)` : ""}</TableCell>
                  <TableCell className="text-xs tabular">{t.archives ? `${t.archivedEvents.toLocaleString()} events · ${t.archives} days · ${bytes(t.archivedBytes)}` : "—"}</TableCell>
                  <TableCell className="text-xs tabular">{t.earliest ? `${t.earliest.toISOString().slice(0, 10)} (${t.coveredDays} days)` : "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Legal holds</CardTitle>
          <CardDescription>Nothing in a hold&apos;s range is deleted, whatever the retention says, until the hold is released. Placing and releasing a hold both need a reason and are in the audit log.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {holds.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Client</TableHead>
                  <TableHead>Range</TableHead>
                  <TableHead>Why</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {holds.map((h) => (
                  <TableRow key={h.id}>
                    <TableCell className="text-xs">{h.tenantName}</TableCell>
                    <TableCell className="text-xs tabular">{h.fromAt.toISOString().slice(0, 10)} → {h.toAt ? h.toAt.toISOString().slice(0, 10) : "open-ended"}</TableCell>
                    <TableCell className="max-w-80 whitespace-normal text-xs">{h.reason}{h.caseId && <span className="block font-mono text-[11px] text-muted-foreground">case {h.caseId}</span>}</TableCell>
                    <TableCell className="text-xs">{h.releasedAt ? <span className="text-muted-foreground">Released {formatDateTime(h.releasedAt)}: {h.releaseReason}</span> : <Badge variant="warning">In force</Badge>}</TableCell>
                    <TableCell className="text-right">{canEdit && !h.releasedAt && <ReleaseHold id={h.id} />}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {canEdit && <HoldForm tenants={report.tenants.map((t) => ({ id: t.id, name: t.name }))} />}
        </CardContent>
      </Card>

      {archives.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent archives</CardTitle>
            <CardDescription>Each download is decrypted and checked against the hash recorded when it was written, and goes in the audit log.</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Day</TableHead>
                  <TableHead>Client</TableHead>
                  <TableHead>Events</TableHead>
                  <TableHead>Size</TableHead>
                  <TableHead>SHA-256</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {archives.map((a) => (
                  <TableRow key={a.id}>
                    <TableCell className="text-xs tabular">{a.day.toISOString().slice(0, 10)}{a.part > 1 ? ` · part ${a.part}` : ""}</TableCell>
                    <TableCell className="text-xs">{a.tenant?.name ?? "Internal"}</TableCell>
                    <TableCell className="text-xs tabular">{a.events.toLocaleString()}</TableCell>
                    <TableCell className="text-xs tabular">{bytes(a.bytes)}</TableCell>
                    <TableCell className="font-mono text-[11px]">{a.sha256.slice(0, 16)}…</TableCell>
                    <TableCell className="text-right">{(canEdit || can(user, "audit.export")) && <a className="text-xs hover:underline" href={`/retention/archives/${a.id}`}>Download</a>}</TableCell>
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
