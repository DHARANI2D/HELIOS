import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, CheckCircle2, Clock, Download, FileUp, Globe, ShieldCheck } from "lucide-react";

import { dbFor } from "@/lib/tenant-db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { formatDateTime } from "@/lib/format";
import { CHECKS, type CheckKey } from "@/lib/testing/exposure";
import { IMPORT_TOOLS } from "@/lib/testing/imports";
import { SEVERITIES, severityCounts } from "@/lib/testing/findings";
import { verifyRecord } from "@/lib/testing/scope";
import { attestationText, findingsOf, targetsOf } from "@/lib/testing/service";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TestStatusBadge } from "@/components/testing/status-badge";
import { AuthoriseButton, FindingStatus, ImportForm, RetestButton, StopButton, VerifyButton } from "@/components/testing/test-controls";

const SEV_VARIANT = { critical: "destructive", high: "warning", medium: "outline", low: "soft", info: "soft" } as const;

type Probe = { at: string; target: string; check: string; result: string };
type Import = { tool: string; file: string; at: string; by: string; kept: number; outOfScope: number };

export default async function SecurityTestPage({ params }: PageProps<"/testing/[id]">) {
  const { id } = await params;
  const user = await pageGuard("testing.view");
  const test = await dbFor(user).securityTest.findUnique({ where: { id }, include: { tenant: { select: { name: true } } } });
  if (!test || (user.isClient && user.tenantId !== test.tenantId)) notFound();
  const now = new Date();
  const targets = targetsOf(test);
  const findings = findingsOf(test);
  const counts = severityCounts(findings);
  const probes = (test.probes as unknown as Probe[] | null) ?? [];
  const imports = (test.imports as unknown as Import[] | null) ?? [];
  const inWindow = now >= test.windowStart && now < test.windowEnd;
  const record = verifyRecord(test.verifyToken);
  const allVerified = targets.length > 0 && targets.every((t) => t.verified);
  const open = ["requested", "authorised", "queued", "running", "completed"].includes(test.status);
  const canRequest = can(user, "testing.request");
  const canAuthClient = user.isClient && user.role === "CLIENT_ADMIN" && can(user, "testing.authorise") && !test.clientAuthorisedAt && test.status === "requested";
  const canAuthHelios = !user.isClient && (user.role === "ADMIN" || user.role === "SOC_MANAGER") && !test.heliosAuthorisedAt && test.status === "requested" && test.requestedById !== user.id;
  const canAccept = user.isClient ? user.role === "CLIENT_ADMIN" : user.role === "ADMIN" || user.role === "SOC_MANAGER";

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-2">
        <Button variant="ghost" size="sm" asChild className="-ml-2"><Link href="/testing"><ArrowLeft /> Security testing</Link></Button>
        <div className="flex gap-2">
          {open && (canRequest || can(user, "testing.authorise")) && <StopButton testId={test.id} label={test.status === "requested" ? "Reject" : "Stop the test"} />}
          <Button variant="outline" size="sm" asChild><a href={`/testing/${test.id}/pdf`}><Download /> Report PDF</a></Button>
        </div>
      </div>

      <Card className="surface-glow">
        <CardHeader>
          <div className="flex flex-wrap items-center gap-2">
            <TestStatusBadge status={test.status} />
            {!user.isClient && <Badge variant="outline">{test.tenant.name}</Badge>}
            {inWindow && ["authorised", "queued", "running", "completed"].includes(test.status) && <Badge variant="info"><Clock /> Window open</Badge>}
          </div>
          <CardTitle className="mt-2 text-xl">{test.title}</CardTitle>
          <CardDescription>
            {formatDateTime(test.windowStart)} → {formatDateTime(test.windowEnd)} · {test.checks.map((c) => CHECKS[c as CheckKey] ?? c).join(" · ")}
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 text-sm sm:grid-cols-4">
          {SEVERITIES.filter((s) => s !== "info").map((s) => (
            <div key={s}>
              <div className="text-xs text-muted-foreground capitalize">{s} open</div>
              <div className="text-lg font-semibold tabular-nums">{counts[s]}</div>
            </div>
          ))}
          {test.closedReason && <p className="text-xs text-muted-foreground sm:col-span-4">{test.status === "rejected" ? "Rejected" : "Stopped"} by {test.closedByName}: {test.closedReason}</p>}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><Globe className="size-4" /> Scope</CardTitle>
            <CardDescription>
              Prove control of each name with a DNS TXT record on the name or on <code>_helios-verify.&lt;name&gt;</code>: <code className="break-all">{record}</code>. A host under a verified name, and an address a verified name resolves to, count as verified.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <Table>
              <TableHeader>
                <TableRow><TableHead>Target</TableHead><TableHead>Proof</TableHead></TableRow>
              </TableHeader>
              <TableBody>
                {targets.map((t) => (
                  <TableRow key={t.value}>
                    <TableCell className="font-mono text-xs">{t.value}{t.addresses.length > 0 && t.kind !== "ip" && <div className="text-[10px] text-muted-foreground">{t.addresses.slice(0, 4).join(", ")}</div>}</TableCell>
                    <TableCell className="text-xs">{t.verified ? <span className="flex items-center gap-1 text-success-ink"><CheckCircle2 className="size-3.5" /> {t.via}</span> : <span className="text-muted-foreground">{t.problem ?? "Not checked yet"}</span>}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {["requested", "authorised"].includes(test.status) && <div><VerifyButton testId={test.id} /></div>}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><ShieldCheck className="size-4" /> Authorisation</CardTitle>
            <CardDescription>Both the client&apos;s admin and a HELIOS approver who didn&apos;t ask for it. Then HELIOS runs it on its own when the window opens, checking the DNS proof again first.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4 text-sm">
            <div className="flex flex-col gap-1">
              <p className="font-medium">The client</p>
              {test.clientAuthorisedAt ? (
                <p className="text-xs text-muted-foreground">{test.clientAuthorisedByName} on {formatDateTime(test.clientAuthorisedAt)}: &ldquo;{test.clientAttestation}&rdquo;</p>
              ) : canAuthClient && allVerified ? (
                <AuthoriseButton testId={test.id} attestation={attestationText(test, test.tenant.name, targets)} />
              ) : (
                <p className="text-xs text-muted-foreground">{allVerified ? "Waiting for the client's admin." : "Waiting for every target to be verified."}</p>
              )}
            </div>
            <div className="flex flex-col gap-1">
              <p className="font-medium">HELIOS</p>
              {test.heliosAuthorisedAt ? (
                <p className="text-xs text-muted-foreground">{test.heliosAuthorisedByName} on {formatDateTime(test.heliosAuthorisedAt)}</p>
              ) : canAuthHelios && allVerified ? (
                <AuthoriseButton testId={test.id} attestation={null} />
              ) : (
                <p className="text-xs text-muted-foreground">{allVerified ? "Waiting for a SOC manager or admin (not the person who asked)." : "Waiting for every target to be verified."}</p>
              )}
            </div>
            <div className="flex flex-col gap-1">
              <p className="font-medium">Rules of engagement</p>
              <p className="text-xs whitespace-pre-wrap text-muted-foreground">{test.rulesOfEngagement}</p>
              <p className="text-xs text-muted-foreground">Asked by {test.requestedByName} on {formatDateTime(test.createdAt)}.</p>
            </div>
            <div className="flex flex-wrap items-center gap-2 border-t pt-3 text-xs text-muted-foreground">
              {test.runs ? `${test.runs} run(s); last finished ${test.finishedAt ? formatDateTime(test.finishedAt) : "—"}.` : test.status === "authorised" ? `Runs on its own from ${formatDateTime(test.windowStart)}.` : "Not run yet."}
              {test.status === "running" && <Badge variant="secondary">Running now</Badge>}
              {canRequest && inWindow && ["completed", "authorised"].includes(test.status) && <RetestButton testId={test.id} />}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Findings ({findings.length})</CardTitle>
          <CardDescription>Worst first. A re-test marks what it no longer finds as fixed; a risk the client chooses to carry is accepted with the reason.</CardDescription>
        </CardHeader>
        <CardContent>
          {findings.length === 0 ? (
            <p className="text-sm text-muted-foreground">{test.runs || imports.length ? "Nothing found." : "No results yet."}</p>
          ) : (
            <div className="flex flex-col divide-y">
              {findings.map((f) => (
                <div key={f.id} className="flex flex-wrap items-start justify-between gap-3 py-3 first:pt-0 last:pb-0">
                  <div className="flex min-w-0 flex-1 flex-col gap-1">
                    <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
                      <Badge variant={SEV_VARIANT[f.severity]} className="capitalize">{f.severity}</Badge>
                      <span className={f.status !== "open" ? "text-muted-foreground line-through" : ""}>{f.title}</span>
                      <span className="font-mono text-xs text-muted-foreground">{f.target}{f.port ? `:${f.port}` : ""}</span>
                    </p>
                    <p className="text-xs whitespace-pre-wrap text-muted-foreground">{f.evidence}</p>
                    <p className="text-xs"><span className="font-medium">Fix:</span> {f.remediation}</p>
                    <p className="text-[11px] text-muted-foreground">{f.source} · first seen {formatDateTime(f.firstSeen)}{f.references.length ? ` · ${f.references.slice(0, 4).join(", ")}` : ""}{f.statusNote ? ` · ${f.statusNote}` : ""}</p>
                  </div>
                  {canRequest ? <FindingStatus testId={test.id} findingId={f.id} status={f.status} canAccept={canAccept} /> : <Badge variant="outline" className="capitalize">{f.status}</Badge>}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><FileUp className="size-4" /> Scanner results</CardTitle>
          <CardDescription>Deeper scans run in an established scanner under this same authorisation. Add the report here: findings on targets outside this test&apos;s verified scope are left out.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {canRequest && ["authorised", "queued", "running", "completed"].includes(test.status) && <ImportForm testId={test.id} tools={Object.fromEntries(Object.entries(IMPORT_TOOLS).map(([k, v]) => [k, v.label]))} />}
          {imports.length > 0 ? (
            <ul className="text-xs text-muted-foreground">
              {imports.map((i, n) => <li key={n}>{IMPORT_TOOLS[i.tool as keyof typeof IMPORT_TOOLS]?.label ?? i.tool}: {i.file}, added by {i.by} on {formatDateTime(i.at)}; {i.kept} kept, {i.outOfScope} out of scope</li>)}
            </ul>
          ) : (
            <p className="text-xs text-muted-foreground">None added.</p>
          )}
        </CardContent>
      </Card>

      {probes.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">What HELIOS probed (last run)</CardTitle>
          </CardHeader>
          <CardContent>
            <details>
              <summary className="cursor-pointer text-sm text-muted-foreground">{probes.length} probe(s)</summary>
              <div className="mt-2 max-h-96 overflow-auto font-mono text-[11px]">
                {probes.map((p, i) => <div key={i}>{p.at.replace("T", " ").slice(0, 19)}  {p.target}  {p.check}  {p.result}</div>)}
              </div>
            </details>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
