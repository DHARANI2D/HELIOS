import Link from "next/link";
import { AlarmClock, CheckCircle2, Download, FileCheck2, Landmark, ShieldQuestion } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { selectedTenantId, tenantScope } from "@/lib/access";
import { formatDateTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { CERT_IN_CATEGORIES, CERT_IN_CONTACT, CERT_IN_HOURS } from "@/lib/compliance/cert-in";
import { DPDP_REPORT_HOURS, DPDP_RULE7_FROM, dpdpInForce } from "@/lib/compliance/dpdp";
import { NOTICE_LABEL, SUBMIT_CHANNELS, clockOf, formatSpan, type ClockState } from "@/lib/compliance/notices";
import { evidenceMap, type EvidenceStatus } from "@/lib/compliance/iso27001";
import { StatTile } from "@/components/dashboard/stat-tile";
import { EmptyState } from "@/components/shared/empty-state";
import { TestBadge } from "@/components/shared/test-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const PERIODS = [30, 90, 365];
const CLOCK_TONE: Record<ClockState, string> = { running: "text-info-ink", due_soon: "text-warning-ink", overdue: "text-destructive", met: "text-success-ink", late: "text-destructive", closed: "text-muted-foreground" };
const EVIDENCE_VARIANT: Record<EvidenceStatus, "success" | "warning" | "outline"> = { evidenced: "success", partial: "warning", gap: "outline" };
const EVIDENCE_LABEL: Record<EvidenceStatus, string> = { evidenced: "Evidenced", partial: "Partly evidenced", gap: "Gap" };
const STATUS_LABEL = { DRAFT: "Draft", AWAITING_APPROVAL: "With the client", APPROVED: "Approved, not filed", SUBMITTED: "Filed", NOT_REQUIRED: "Not required" } as const;

function clockText(n: Parameters<typeof clockOf>[0], now: Date) {
  const c = clockOf(n, now);
  const text =
    c.state === "overdue" ? `Overdue by ${formatSpan(-(c.marginMs ?? 0))}`
      : c.state === "late" ? `${formatSpan(-(c.marginMs ?? 0))} late`
        : c.state === "met" ? (c.marginMs != null ? `On time, ${formatSpan(c.marginMs)} to spare` : "Filed")
          : c.marginMs != null ? `${formatSpan(c.marginMs)} left` : "—";
  return { state: c.state, text };
}

export default async function CompliancePage({ searchParams }: PageProps<"/compliance">) {
  const user = await pageGuard("compliance.view");
  const sp = await searchParams;
  const days = PERIODS.includes(Number(sp.days)) ? Number(sp.days) : 90;
  const now = new Date();
  const [scope, selected] = await Promise.all([tenantScope(user), selectedTenantId(user)]);
  const tenantFilter = scope.tenantId ? { tenantId: scope.tenantId } : {};
  const since = new Date(now.getTime() - days * 86_400_000);

  const [open, recent, tenant, evidence] = await Promise.all([
    db.regulatoryNotice.findMany({
      where: { ...tenantFilter, status: { in: ["DRAFT", "AWAITING_APPROVAL", "APPROVED"] } },
      include: { case: { select: { id: true, title: true } }, tenant: { select: { name: true, isTest: true } } },
      orderBy: [{ dueAt: { sort: "asc", nulls: "last" } }, { createdAt: "asc" }],
      take: 200,
    }),
    db.regulatoryNotice.findMany({
      where: { ...tenantFilter, status: { in: ["SUBMITTED", "NOT_REQUIRED"] }, updatedAt: { gte: since } },
      include: { case: { select: { id: true, title: true } }, tenant: { select: { name: true, isTest: true } } },
      orderBy: { updatedAt: "desc" },
      take: 100,
    }),
    selected ? db.tenant.findUnique({ where: { id: selected }, select: { name: true, isTest: true } }) : Promise.resolve(null),
    evidenceMap(selected, days, now),
  ]);

  const overdue = open.filter((n) => n.dueAt && n.dueAt < now).length;
  const filed = recent.filter((n) => n.status === "SUBMITTED");
  const onTime = filed.filter((n) => !n.dueAt || n.submittedAt! <= n.dueAt).length;
  const staff = !user.isClient;
  const heading = user.isClient ? `Compliance — ${user.tenantName ?? "your organization"}` : tenant ? `Compliance — ${tenant.name}` : "Compliance — all clients";

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="flex items-center gap-2 text-sm text-muted-foreground"><Landmark className="size-4" /> CERT-In · DPDP · ISO/IEC 27001</p>
          <h2 className="flex items-center gap-2 text-xl font-semibold tracking-tight">{heading}{tenant?.isTest && <TestBadge />}</h2>
        </div>
        <nav aria-label="Period" className="flex rounded-md border p-0.5">
          {PERIODS.map((d) => (
            <Link key={d} href={`/compliance?days=${d}`} aria-current={days === d ? "page" : undefined} className={cn("rounded px-2.5 py-1 text-xs font-medium text-muted-foreground hover:text-foreground", days === d && "bg-muted text-foreground")}>
              {d === 365 ? "12 months" : `${d} days`}
            </Link>
          ))}
        </nav>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatTile label="Open notices" value={open.length} icon={AlarmClock} hint={open.length ? `${open.filter((n) => n.status === "AWAITING_APPROVAL").length} waiting for the client` : "Nothing to file"} />
        <StatTile label="Overdue" value={overdue} icon={ShieldQuestion} tone={overdue ? "warning" : "default"} hint={overdue ? "Past the deadline and not filed" : "None past a deadline"} />
        <StatTile label={`Filed in ${days === 365 ? "12 months" : `${days} days`}`} value={filed.length} icon={FileCheck2} hint={filed.length ? `${onTime} on time` : undefined} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Clocks running</CardTitle>
          <CardDescription>Every notice not yet filed, the nearest deadline first. Open the case to draft, approve or file it.</CardDescription>
        </CardHeader>
        <CardContent>
          {open.length === 0 ? (
            <EmptyState icon={CheckCircle2} title="No regulatory clocks running" description={`A case of a type CERT-In lists opens a report here on its own, with ${CERT_IN_HOURS} hours from when it was noticed. Analysts can start one, or a DPDP breach workflow, from any case.`} />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Notice</TableHead>
                  {staff && <TableHead>Client</TableHead>}
                  <TableHead>Case</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Due</TableHead>
                  <TableHead>Clock</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {open.map((n) => {
                  const c = clockText(n, now);
                  return (
                    <TableRow key={n.id}>
                      <TableCell className="text-xs font-medium">{NOTICE_LABEL[n.kind]}{n.sequence > 1 ? ` · update ${n.sequence - 1}` : ""}</TableCell>
                      {staff && <TableCell className="text-xs">{n.tenant.name}{n.tenant.isTest && <TestBadge className="ml-1" />}</TableCell>}
                      <TableCell className="max-w-72 truncate text-xs"><Link href={`/cases/${n.case.id}#regulatory`} className="hover:underline">{n.case.title}</Link></TableCell>
                      <TableCell><Badge variant={n.status === "AWAITING_APPROVAL" ? "warning" : n.status === "APPROVED" ? "soft" : "outline"}>{STATUS_LABEL[n.status]}</Badge></TableCell>
                      <TableCell className="text-xs tabular">{n.dueAt ? formatDateTime(n.dueAt) : "No fixed deadline"}</TableCell>
                      <TableCell className={cn("text-xs font-medium tabular", CLOCK_TONE[c.state])}>{c.text}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Filed and closed</CardTitle>
          <CardDescription>Notices filed, or found not to be needed, in this period.</CardDescription>
        </CardHeader>
        <CardContent>
          {recent.length === 0 ? (
            <p className="text-sm text-muted-foreground">Nothing in this period.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Notice</TableHead>
                  {staff && <TableHead>Client</TableHead>}
                  <TableHead>Case</TableHead>
                  <TableHead>Outcome</TableHead>
                  <TableHead>Timing</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recent.map((n) => {
                  const c = clockText(n, now);
                  return (
                    <TableRow key={n.id}>
                      <TableCell className="text-xs font-medium">{NOTICE_LABEL[n.kind]}{n.sequence > 1 ? ` · update ${n.sequence - 1}` : ""}</TableCell>
                      {staff && <TableCell className="text-xs">{n.tenant.name}</TableCell>}
                      <TableCell className="max-w-72 truncate text-xs"><Link href={`/cases/${n.case.id}#regulatory`} className="hover:underline">{n.case.title}</Link></TableCell>
                      <TableCell className="text-xs">
                        {n.status === "SUBMITTED"
                          ? `Filed ${formatDateTime(n.submittedAt!)} · ${SUBMIT_CHANNELS[n.submittedVia as keyof typeof SUBMIT_CHANNELS] ?? n.submittedVia}${n.reference ? ` · ${n.reference}` : ""}`
                          : `Not required: ${n.notRequiredReason ?? ""}`}
                      </TableCell>
                      <TableCell className={cn("text-xs tabular", CLOCK_TONE[c.state])}>{n.status === "SUBMITTED" ? c.text : "—"}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div>
              <CardTitle className="text-base">ISO/IEC 27001:2022 evidence</CardTitle>
              <CardDescription>
                What HELIOS&apos;s own records show for the Annex A controls it touches, over the last {days === 365 ? "12 months" : `${days} days`}{selected || user.isClient ? "" : " across every client (pick a client for its own rulebook, keys and users)"}. Evidence for an auditor, not a certificate: a gap means HELIOS has nothing to show for it.
              </CardDescription>
            </div>
            <Button size="sm" variant="outline" asChild><a href={`/compliance/evidence/pdf?days=${days}`}><Download /> PDF</a></Button>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-16">Control</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Evidence</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {evidence.map((c) => (
                <TableRow key={c.id} className="align-top">
                  <TableCell className="font-mono text-xs">A.{c.id}</TableCell>
                  <TableCell className="text-xs font-medium">{c.name}</TableCell>
                  <TableCell><Badge variant={EVIDENCE_VARIANT[c.status]}>{EVIDENCE_LABEL[c.status]}</Badge></TableCell>
                  <TableCell className="text-xs whitespace-normal">
                    <ul className="flex flex-col gap-0.5">
                      {c.evidence.map((e) => (
                        <li key={e.label}>
                          <span className="text-muted-foreground">{e.label}:</span> {e.href ? <Link href={e.href} className="hover:underline">{e.value}</Link> : e.value}
                        </li>
                      ))}
                    </ul>
                    {c.note && <p className="mt-1 text-[11px] text-muted-foreground">{c.note}</p>}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">The rules HELIOS follows</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 text-xs lg:grid-cols-2">
          <div className="flex flex-col gap-2">
            <p className="font-medium">CERT-In directions of 28 April 2022</p>
            <p className="text-muted-foreground">
              Service providers, intermediaries, data centres, body corporates and government organisations report the incidents below to CERT-In within {CERT_IN_HOURS} hours of noticing them, at {CERT_IN_CONTACT.email} ({CERT_IN_CONTACT.phone}). HELIOS proposes the type from the case&apos;s techniques, detections and assets; an analyst confirms it, and the client approves the report.
            </p>
            <details>
              <summary className="cursor-pointer font-medium">The {CERT_IN_CATEGORIES.length} reportable incident types (Annexure I)</summary>
              <ol className="mt-1 flex flex-col gap-0.5">
                {CERT_IN_CATEGORIES.map((c) => <li key={c.code}><span className="font-mono">({c.code})</span> {c.label}</li>)}
              </ol>
            </details>
          </div>
          <div className="flex flex-col gap-2">
            <p className="font-medium">DPDP Rules, 2025 — Rule 7 {dpdpInForce(now) ? "(in force)" : `(applies from ${DPDP_RULE7_FROM.toISOString().slice(0, 10)})`}</p>
            <p className="text-muted-foreground">
              A Data Fiduciary that becomes aware of a personal data breach tells each person affected and the Data Protection Board without delay, and sends the Board a detailed report within {DPDP_REPORT_HOURS} hours (longer only if the Board allows). &ldquo;Without delay&rdquo; has no number in law; each client sets its own target in its rulebook.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
