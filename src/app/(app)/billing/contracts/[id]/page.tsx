import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, Download } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { formatDateTime } from "@/lib/format";
import { formatMoney, fromMinor } from "@/lib/billing/terms";
import { parseCriteria, parseProfile, pilotReport } from "@/lib/billing/service";
import { BillingProfileForm, ContractActions, ContractForm, InvoiceActions } from "@/components/billing/billing-controls";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const AUTONOMY: Record<string, string> = { OFF: "No AI involvement", SUGGEST: "Suggest only", CONTAIN_WITH_APPROVAL: "Contain with approval", AUTO_CONTAIN: "Contain on its own within the rulebook" };
const day = (d: Date | null) => (d ? d.toISOString().slice(0, 10) : "—");

export default async function ContractPage({ params }: PageProps<"/billing/contracts/[id]">) {
  const { id } = await params;
  const user = await pageGuard("billing.view");
  const c = await db.contract.findUnique({ where: { id }, include: { tenant: { select: { id: true, name: true, billingProfile: true } }, invoices: { orderBy: { periodFrom: "desc" } } } });
  if (!c || (user.isClient && c.tenantId !== user.tenantId)) notFound();
  const canManage = can(user, "billing.manage");
  const pilot = c.kind === "PILOT";
  const report = pilot && c.status !== "DRAFT" && c.status !== "SENT" ? await pilotReport(c) : null;
  const converted = c.convertedToId ? await db.contract.findUnique({ where: { id: c.convertedToId }, select: { id: true, reference: true } }) : null;
  const months = c.termMonths;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <Button variant="ghost" size="sm" asChild className="-ml-2"><Link href="/billing"><ArrowLeft /> Contracts & Billing</Link></Button>
        <Button variant="outline" size="sm" asChild><a href={`/billing/contracts/${c.id}/pdf`}><Download /> {pilot ? "Pilot agreement" : "Order form"} PDF</a></Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">{c.reference} · {c.tenant.name} <Badge variant="outline">{pilot ? "pilot" : "subscription"}</Badge> <Badge variant={c.status === "ACTIVE" ? "success" : c.status === "SENT" ? "warning" : "outline"}>{c.status.toLowerCase()}</Badge></CardTitle>
          <CardDescription>
            {day(c.startsAt)} to {day(c.endsAt)} ({months} month{months === 1 ? "" : "s"}){c.autoRenew ? ", renews for the same term" : ""}. {c.planName ?? "Managed detection and response"}, {c.endpointsCommitted.toLocaleString()} endpoints, {formatMoney(c.monthlyFee, c.currency)} a month{c.overagePerEndpoint ? `, ${formatMoney(c.overagePerEndpoint, c.currency)} per endpoint above` : ""}{c.oneTimeFee ? `, ${formatMoney(c.oneTimeFee, c.currency)} one-time` : ""}; invoiced {c.billingCycle}, payable in {c.paymentTermsDays} days.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4 text-sm">
          <div className="grid gap-2 sm:grid-cols-3">
            <div className="rounded-md border p-2"><p className="text-xs text-muted-foreground">AI autonomy agreed</p><p>{c.autonomyCap ? AUTONOMY[c.autonomyCap] : "Recorded when sent"}</p></div>
            <div className="rounded-md border p-2"><p className="text-xs text-muted-foreground">Rulebook in force</p><p>{c.rulebookVersion ? `Version ${c.rulebookVersion}` : c.sentAt ? "None signed" : "Recorded when sent"}</p></div>
            <div className="rounded-md border p-2"><p className="text-xs text-muted-foreground">Liability for automated containment</p><p>{c.liabilityCapMonths ? `Capped at ${c.liabilityCapMonths} months of fees` : "Per the terms"}{c.dpaReference ? ` · DPA ${c.dpaReference}` : ""}</p></div>
          </div>
          {c.signedAt && <p className="text-xs text-muted-foreground">Signed by {c.signedByName}{c.signedByTitle ? `, ${c.signedByTitle}` : ""}, {formatDateTime(c.signedAt)} ({c.signedVia === "in_app" ? "in HELIOS" : c.signedVia === "e_sign" ? "e-signature" : "paper"}).</p>}
          {c.endedAt && <p className="text-xs text-muted-foreground">Ended {day(c.endedAt)}: {c.endReason}</p>}
          {converted && <p className="text-xs">Converted into <Link href={`/billing/contracts/${converted.id}`} className="font-medium hover:underline">{converted.reference}</Link>.</p>}
          {c.pilotOutcome === "not_converted" && <p className="text-xs text-muted-foreground">The pilot didn&apos;t continue.</p>}
          <ContractActions id={c.id} status={c.status} kind={c.kind} canManage={canManage} canSignAsClient={user.isClient && user.role === "CLIENT_ADMIN"} converted={c.convertedToId} outcome={c.pilotOutcome} />
        </CardContent>
      </Card>

      {pilot && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Pilot success criteria</CardTitle>
            <CardDescription>Measured from HELIOS&apos;s own records over the pilot, so both sides see the same numbers.</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="flex flex-col gap-1 text-sm">
              {(report?.criteria ?? parseCriteria(c.successCriteria).map((x) => ({ ...x, label: x.metric, value: null, met: null }))).map((x, i) => (
                <li key={i} className={x.met === false ? "text-destructive" : x.met ? "text-success-ink" : ""}>
                  {x.met === null ? "○" : x.met ? "✓" : "✗"} {x.label}: {x.value ?? (report ? "no data yet" : "measured once signed")} <span className="text-muted-foreground">(target {x.target})</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {canManage && c.status === "DRAFT" && (
        <Card>
          <CardHeader><CardTitle className="text-base">Edit the draft</CardTitle></CardHeader>
          <CardContent>
            <ContractForm
              tenants={[]}
              tenantId={c.tenantId}
              contractId={c.id}
              initial={{ kind: c.kind, currency: c.currency, planName: c.planName ?? "", monthlyFee: fromMinor(c.monthlyFee), endpointsCommitted: c.endpointsCommitted, overagePerEndpoint: fromMinor(c.overagePerEndpoint), oneTimeFee: fromMinor(c.oneTimeFee), billingCycle: c.billingCycle as "monthly", paymentTermsDays: c.paymentTermsDays, startsAt: day(c.startsAt), months, autoRenew: c.autoRenew, noticeDays: c.noticeDays, liabilityCapMonths: c.liabilityCapMonths, successCriteria: parseCriteria(c.successCriteria) }}
            />
          </CardContent>
        </Card>
      )}

      {canManage && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Bill to</CardTitle>
            <CardDescription>{c.tenant.name}&apos;s billing details, used for every invoice issued from now on.</CardDescription>
          </CardHeader>
          <CardContent><BillingProfileForm tenantId={c.tenantId} contractId={c.id} value={parseProfile(c.tenant.billingProfile)} /></CardContent>
        </Card>
      )}

      {c.invoices.length > 0 && (
        <Card>
          <CardHeader><CardTitle className="text-base">Invoices</CardTitle></CardHeader>
          <CardContent>
            <ul className="divide-y text-xs">
              {c.invoices.filter((i) => !user.isClient || i.status !== "DRAFT").map((i) => (
                <li key={i.id} className="flex items-center justify-between gap-2 py-1.5">
                  <span>
                    {i.number ? <a href={`/billing/invoices/${i.id}/pdf`} className="font-mono hover:underline">{i.number}</a> : <span className="text-muted-foreground">draft</span>} · {day(i.periodFrom)} · {formatMoney(i.total, i.currency)} · {i.status.toLowerCase()}
                  </span>
                  {canManage && <InvoiceActions id={i.id} status={i.status} />}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
