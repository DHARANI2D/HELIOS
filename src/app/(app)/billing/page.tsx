import Link from "next/link";
import { AlertTriangle, FileSignature, IndianRupee, Receipt } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { getSetting } from "@/lib/settings";
import { formatMoney } from "@/lib/billing/terms";
import { pilotReport } from "@/lib/billing/service";
import { BillingSettingsForm, ContractForm, DraftDueInvoices, FromQuoteForm, InvoiceActions } from "@/components/billing/billing-controls";
import { StatTile } from "@/components/dashboard/stat-tile";
import { TestBadge } from "@/components/shared/test-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const DAY = 86_400_000;
const STATUS_VARIANT = { DRAFT: "outline", SENT: "warning", ACTIVE: "success", ENDED: "secondary", TERMINATED: "destructive" } as const;
const INVOICE_VARIANT: Record<string, "outline" | "warning" | "success" | "destructive"> = { DRAFT: "outline", ISSUED: "warning", PAID: "success", VOID: "destructive" };
const day = (d: Date | null) => (d ? d.toISOString().slice(0, 10) : "—");

// Contracts, pilots and invoices. Clients see their own.
export default async function BillingPage() {
  const user = await pageGuard("billing.view");
  const canManage = can(user, "billing.manage");
  const scope = user.isClient ? { tenantId: user.tenantId! } : {};
  const now = new Date();
  const [contracts, invoices, tenants, quotes, settings] = await Promise.all([
    db.contract.findMany({ where: scope, orderBy: [{ status: "asc" }, { endsAt: "asc" }], include: { tenant: { select: { name: true, isTest: true } } }, take: 200 }),
    db.invoice.findMany({ where: { ...scope, ...(user.isClient ? { status: { not: "DRAFT" } } : {}) }, orderBy: [{ createdAt: "desc" }], include: { contract: { select: { reference: true } } }, take: 100 }),
    user.isClient ? Promise.resolve([]) : db.tenant.findMany({ where: { status: { not: "SUSPENDED" } }, select: { id: true, name: true }, orderBy: { name: "asc" } }),
    canManage ? db.quote.findMany({ where: { status: { in: ["SENT", "ACCEPTED"] }, source: "app" }, orderBy: { createdAt: "desc" }, take: 50, select: { id: true, reference: true, clientName: true, tenantId: true } }) : Promise.resolve([]),
    canManage ? getSetting("billing") : Promise.resolve(null),
  ]);
  const tenantName = new Map(contracts.map((c) => [c.tenantId, c.tenant.name]));
  const active = contracts.filter((c) => c.status === "ACTIVE");
  // Recurring revenue by currency, real clients only.
  const mrr = new Map<string, number>();
  for (const c of active.filter((c) => c.kind === "SUBSCRIPTION" && !c.tenant.isTest)) mrr.set(c.currency, (mrr.get(c.currency) ?? 0) + c.monthlyFee);
  const open = invoices.filter((i) => i.status === "ISSUED");
  const overdue = open.filter((i) => i.dueAt && i.dueAt < now);
  const receivable = new Map<string, number>();
  for (const i of open) receivable.set(i.currency, (receivable.get(i.currency) ?? 0) + i.total);
  const pilots = await Promise.all(contracts.filter((c) => c.kind === "PILOT" && c.status === "ACTIVE").map(async (c) => ({ c, r: await pilotReport(c, now) })));
  const sums = (m: Map<string, number>) => [...m.entries()].map(([cur, v]) => formatMoney(v, cur)).join(" + ") || "—";

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
        <StatTile label="Active contracts" value={active.length} icon={FileSignature} hint={`${active.filter((c) => c.kind === "PILOT").length} pilots`} />
        {!user.isClient && <StatTile label="Monthly recurring" value={sums(mrr)} icon={IndianRupee} hint="Signed subscriptions, test clients left out" />}
        <StatTile label="Unpaid invoices" value={open.length} icon={Receipt} hint={sums(receivable)} />
        <StatTile label="Overdue" value={overdue.length} icon={AlertTriangle} tone={overdue.length ? "critical" : "default"} />
      </div>

      {pilots.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Pilots running</CardTitle>
            <CardDescription>Success criteria measured from HELIOS&apos;s own records since each pilot started.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {pilots.map(({ c, r }) => (
              <div key={c.id} className="rounded-md border p-3">
                <div className="flex items-center justify-between">
                  <Link href={`/billing/contracts/${c.id}`} className="text-sm font-medium hover:underline">{c.reference} · {c.tenant.name}</Link>
                  <span className="text-xs text-muted-foreground">{Math.max(0, Math.ceil((c.endsAt.getTime() - now.getTime()) / DAY))} days left</span>
                </div>
                <ul className="mt-1 grid gap-0.5 text-xs sm:grid-cols-2">
                  {r.criteria.map((x, i) => (
                    <li key={i} className={x.met === false ? "text-destructive" : x.met ? "text-success-ink" : "text-muted-foreground"}>
                      {x.met === null ? "○" : x.met ? "✓" : "✗"} {x.label}: {x.value ?? "no data yet"} (target {x.target})
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Contracts</CardTitle>
          <CardDescription>
            {user.isClient ? "Your agreements with us. A contract waiting for your signature can be signed on its page." : "Drafted, sent to the client, and signed in the app by the client's admin or recorded from paper or e-signature. Sending and signing record the AI autonomy the client consented to and the rulebook version in force."}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {contracts.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Reference</TableHead>
                  {!user.isClient && <TableHead>Client</TableHead>}
                  <TableHead>Status</TableHead>
                  <TableHead>Term</TableHead>
                  <TableHead className="text-right">Monthly</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {contracts.map((c) => (
                  <TableRow key={c.id}>
                    <TableCell className="text-xs"><Link href={`/billing/contracts/${c.id}`} className="font-medium hover:underline">{c.reference}</Link> <span className="text-muted-foreground">{c.kind === "PILOT" ? "pilot" : c.planName ?? ""}</span></TableCell>
                    {!user.isClient && <TableCell className="text-xs">{c.tenant.name}{c.tenant.isTest && <TestBadge className="ml-1" />}</TableCell>}
                    <TableCell><Badge variant={STATUS_VARIANT[c.status]}>{c.status.toLowerCase()}</Badge></TableCell>
                    <TableCell className="text-xs tabular">{day(c.startsAt)} → {day(c.endsAt)}{c.autoRenew && <span className="text-muted-foreground"> · renews</span>}</TableCell>
                    <TableCell className="text-right text-xs tabular">{formatMoney(c.monthlyFee, c.currency)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-sm text-muted-foreground">No contracts yet.</p>
          )}
          {canManage && (
            <>
              <div className="rounded-md border p-3"><p className="mb-2 text-sm font-medium">From a quote</p><FromQuoteForm quotes={quotes} tenants={tenants} /></div>
              <details className="rounded-md border p-3">
                <summary className="cursor-pointer text-sm font-medium">New contract or pilot</summary>
                <div className="mt-3"><ContractForm tenants={tenants} /></div>
              </details>
            </>
          )}
        </CardContent>
      </Card>

      <Card id="invoices" className="scroll-mt-20">
        <CardHeader className="flex flex-row items-start justify-between gap-4">
          <div>
            <CardTitle className="text-base">Invoices</CardTitle>
            <CardDescription>
              {user.isClient ? "Download any invoice as a PDF." : "Drafted each day for every billing period of a signed contract that has started. Issuing numbers it (prefix/financial year/serial) and works out GST from the place of supply; it can't change after that, only be voided with its number kept."}
            </CardDescription>
          </div>
          {canManage && <DraftDueInvoices />}
        </CardHeader>
        <CardContent>
          {invoices.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Number</TableHead>
                  {!user.isClient && <TableHead>Client</TableHead>}
                  <TableHead>Period</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Total</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {invoices.map((i) => (
                  <TableRow key={i.id}>
                    <TableCell className="font-mono text-xs">{i.number ? <a href={`/billing/invoices/${i.id}/pdf`} className="hover:underline">{i.number}</a> : <span className="text-muted-foreground">draft</span>}</TableCell>
                    {!user.isClient && <TableCell className="text-xs">{tenantName.get(i.tenantId) ?? "—"}</TableCell>}
                    <TableCell className="text-xs tabular">{day(i.periodFrom)} → {day(new Date(i.periodTo.getTime() - DAY))}</TableCell>
                    <TableCell className="text-xs">
                      <Badge variant={INVOICE_VARIANT[i.status] ?? "outline"}>{i.status.toLowerCase()}</Badge>
                      {i.status === "ISSUED" && i.dueAt && <span className={`ml-1 ${i.dueAt < now ? "text-destructive" : "text-muted-foreground"}`}>due {day(i.dueAt)}</span>}
                      {i.status === "PAID" && <span className="ml-1 text-muted-foreground">{day(i.paidAt)}{i.paymentRef ? ` · ${i.paymentRef}` : ""}</span>}
                    </TableCell>
                    <TableCell className="text-right text-xs tabular">{formatMoney(i.total, i.currency)}{i.status === "DRAFT" && <span className="block text-muted-foreground">before tax</span>}</TableCell>
                    <TableCell className="text-right">{canManage && <InvoiceActions id={i.id} status={i.status} />}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-sm text-muted-foreground">No invoices yet.</p>
          )}
        </CardContent>
      </Card>

      {settings && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Settings</CardTitle>
            <CardDescription>Your company&apos;s GSTIN is the tax id under Settings → Company profile; its state decides between CGST and SGST (same state) or IGST (another state). A client outside India is billed as an export of services, without GST.</CardDescription>
          </CardHeader>
          <CardContent><BillingSettingsForm value={settings} /></CardContent>
        </Card>
      )}
    </div>
  );
}
