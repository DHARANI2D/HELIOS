import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, Check, CircleCheck, Pencil, X } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { formatMinutes } from "@/lib/plans";
import { CONTROLS } from "@/lib/endpoints/controls";
import { formatMoney, quoteConfigSchema, type QuoteResult } from "@/lib/pricing/calculator";
import { formatDateTime } from "@/lib/format";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { QuoteStatusControl } from "@/components/pricing/quote-status";

// A client-ready proposal: what's included, what it costs, what's assumed.
// Internal cost and margin never appear here.
export default async function QuotePage({ params }: PageProps<"/pricing/quotes/[id]">) {
  const { id } = await params;
  const user = await pageGuard("pricing.view");
  const quote = await db.quote.findUnique({ where: { id }, include: { createdBy: { select: { name: true, email: true } } } });
  if (!quote) notFound();
  const cfg = quoteConfigSchema.parse(quote.config);
  const r = quote.totals as unknown as QuoteResult;
  const money = (usd: number, decimals?: number) => formatMoney(usd, quote.currency, r.fxRate, { decimals });
  const plan = r.plan ?? null;

  return (
    <div className="mx-auto flex max-w-4xl flex-col gap-6">
      <div className="no-print flex flex-wrap items-center justify-between gap-2">
        <Button variant="ghost" size="sm" asChild className="-ml-2">
          <Link href="/pricing"><ArrowLeft /> Build &amp; Price</Link>
        </Button>
        <div className="flex items-center gap-2">
          <QuoteStatusControl quoteId={quote.id} status={quote.status} />
          <Button variant="outline" size="sm" asChild>
            <Link href={`/pricing?quote=${quote.id}`}><Pencil /> Edit</Link>
          </Button>
        </div>
      </div>

      <Card className="surface-glow">
        <CardHeader>
          <CardDescription className="font-mono">{quote.reference} · valid until {quote.validUntil ? formatDateTime(quote.validUntil).slice(0, 10) : "—"}</CardDescription>
          <CardTitle className="text-2xl">Managed security proposal for {quote.clientName}</CardTitle>
          <CardDescription>
            {plan ? `${plan.name}${plan.tagline ? ` — ${plan.tagline}` : ""}. ` : ""}{r.endpoints.toLocaleString()} endpoints, {cfg.profile.users.toLocaleString()} users. Prepared by {quote.createdBy?.name ?? quote.createdBy?.email ?? "HELIOS"}.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[
            ["Monthly", money(r.monthlyNet, 0)],
            ["Annual", money(r.annualRecurring, 0)],
            ["One-time", money(r.oneTime, 0)],
            ["Year 1 total", money(r.year1Total, 0)],
          ].map(([label, value]) => (
            <div key={label}>
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className="text-xl font-semibold">{value}</p>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">What&apos;s included</CardTitle>
        </CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left text-xs text-muted-foreground">
                <th className="py-2 pr-3 font-medium">Item</th>
                <th className="px-2 py-2 font-medium">Detail</th>
                <th className="px-2 py-2 text-right font-medium">Monthly</th>
                <th className="px-2 py-2 text-right font-medium">One-time</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {r.lines.map((l) => (
                <tr key={l.key}>
                  <td className="py-2 pr-3">{l.label}</td>
                  <td className="px-2 py-2 text-xs text-muted-foreground">{l.detail}</td>
                  <td className="px-2 py-2 text-right tabular">{l.monthly ? money(l.monthly) : "—"}</td>
                  <td className="px-2 py-2 text-right tabular">{l.oneTime ? money(l.oneTime, 0) : "—"}</td>
                </tr>
              ))}
              {r.volumeDiscount > 0 && <tr><td className="py-2 pr-3 text-success-ink" colSpan={2}>Volume discount ({r.volumeDiscountPct}%)</td><td className="px-2 py-2 text-right tabular text-success-ink">−{money(r.volumeDiscount)}</td><td /></tr>}
              {r.termDiscount > 0 && <tr><td className="py-2 pr-3 text-success-ink" colSpan={2}>Term discount ({r.termDiscountPct}%)</td><td className="px-2 py-2 text-right tabular text-success-ink">−{money(r.termDiscount)}</td><td /></tr>}
              {r.extraDiscount > 0 && <tr><td className="py-2 pr-3 text-success-ink" colSpan={2}>Additional discount</td><td className="px-2 py-2 text-right tabular text-success-ink">−{money(r.extraDiscount)}</td><td /></tr>}
              <tr className="font-semibold">
                <td className="py-2 pr-3" colSpan={2}>Total</td>
                <td className="px-2 py-2 text-right tabular">{money(r.monthlyNet)}</td>
                <td className="px-2 py-2 text-right tabular">{money(r.oneTime, 0)}</td>
              </tr>
            </tbody>
          </table>
          <dl className="mt-4 grid grid-cols-2 gap-2 text-sm sm:max-w-md">
            {r.amcAnnual > 0 && (<><dt className="text-muted-foreground">Annual maintenance from year 2</dt><dd className="text-right tabular">{money(r.amcAnnual, 0)}</dd></>)}
            {r.tax > 0 && (<><dt className="text-muted-foreground">Tax ({cfg.commercial.taxPct}%), year 1</dt><dd className="text-right tabular">{money(r.tax, 0)}</dd></>)}
            <dt className="text-muted-foreground">3-year total cost of ownership</dt>
            <dd className="text-right tabular">{money(r.threeYearTotal, 0)}</dd>
          </dl>
        </CardContent>
      </Card>

      <div className="grid gap-4 sm:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Service levels</CardTitle>
            <CardDescription>{plan ? `${plan.coverage} analyst coverage${cfg.ai.mode !== "none" ? ", AI first response around the clock" : ""}` : "No service plan on this quote"}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-1 text-sm">
            {plan && (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).filter((s) => plan.ackMinutes[s] != null).map((s) => (
              <p key={s} className="flex justify-between"><span className="text-muted-foreground">Acknowledge {s.toLowerCase()}</span><span>≤ {formatMinutes(plan.ackMinutes[s])}</span></p>
            ))}
            <p className="flex justify-between"><span className="text-muted-foreground">Incident response retainer</span><span>{(plan?.irRetainerHours ?? 0) + cfg.services.irExtraHours} h / year</span></p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Protection coverage</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1 text-sm">
              {r.coverage.map((c) => (
                <li key={c.control} className="flex items-center gap-2">
                  {c.covered ? <CircleCheck className="size-3.5 text-success-ink" /> : c.essential ? <X className="size-3.5 text-destructive" /> : <span className="size-3.5" />}
                  <span className={!c.covered ? "text-muted-foreground" : undefined}>{CONTROLS.find((x) => x.key === c.control)?.label}</span>
                  <span className="ml-auto truncate text-xs text-muted-foreground">{c.by[0] ?? (c.essential ? "client to provide" : "")}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Assumptions</CardTitle>
        </CardHeader>
        <CardContent className="space-y-1 text-xs text-muted-foreground">
          <p className="flex gap-1.5"><Check className="size-3.5 shrink-0" /> Third-party licences at {r.lines.some((l) => l.basis === "list") ? "vendor list prices" : "agreed prices"}; final pricing subject to vendor confirmation.</p>
          <p className="flex gap-1.5"><Check className="size-3.5 shrink-0" /> Amounts in {quote.currency} at 1 USD = {r.fxRate} {quote.currency}.</p>
          {cfg.ai.mode === "cloud" && <p className="flex gap-1.5"><Check className="size-3.5 shrink-0" /> AI usage estimated at ~{r.aiUsage?.alertsPerMonth.toLocaleString()} alerts ({r.aiUsage?.runsPerMonth.toLocaleString()} AI runs) per month on {cfg.ai.model}{r.aiUsage?.source === "history" ? ", based on measured volumes" : ""}.</p>}
          {cfg.ai.mode === "local" && <p className="flex gap-1.5"><Check className="size-3.5 shrink-0" /> Local AI hardware is installed on the client&apos;s premises or a dedicated host; telemetry stays on-prem.</p>}
          <p className="flex gap-1.5"><Check className="size-3.5 shrink-0" /> {cfg.commercial.term === "monthly" ? "Month-to-month, 30 days' notice." : cfg.commercial.term === "annual" ? "12-month term, billed annually in advance." : "36-month term."}</p>
        </CardContent>
      </Card>
      {can(user, "pricing.margin") && (
        <p className="no-print text-center text-xs text-muted-foreground">
          Internal: year-1 cost {money(r.costYear1, 0)}, gross margin {r.grossMarginPct?.toFixed(1) ?? "—"}% (not shown when printed).
        </p>
      )}
    </div>
  );
}
