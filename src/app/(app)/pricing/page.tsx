import Link from "next/link";
import { FileText } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { tenantOptions } from "@/lib/tenants";
import { PRICE_ITEMS } from "@/lib/pricing/catalog";
import { CATEGORIES, TOOLS, UNIT_LABEL } from "@/lib/integrations/catalog";
import { defaultQuoteConfig, formatMoney, quoteConfigSchema, toolLabel, type QuoteResult } from "@/lib/pricing/calculator";
import { loadPriceBook } from "@/lib/pricing/service";
import { formatRelative } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState } from "@/components/shared/empty-state";
import { Configurator } from "@/components/pricing/configurator";
import { PriceBookEditor, type PriceRow } from "@/components/pricing/price-book";

const QUOTE_VARIANT = { DRAFT: "outline", SENT: "info", ACCEPTED: "success", LOST: "soft" } as const;

function one(v: string | string[] | undefined) {
  return Array.isArray(v) ? v[0] : v;
}

async function loadPricing(editId: string | undefined) {
  const now = new Date();
  const [book, quotes, tenants, editing] = await Promise.all([
    loadPriceBook(),
    db.quote.findMany({ orderBy: { updatedAt: "desc" }, take: 30, include: { createdBy: { select: { name: true } }, tenant: { select: { name: true } } } }),
    tenantOptions(),
    editId ? db.quote.findUnique({ where: { id: editId } }) : Promise.resolve(null),
  ]);
  return { now, book, quotes, tenants, editing };
}

export default async function PricingPage({ searchParams }: PageProps<"/pricing">) {
  const user = await pageGuard("pricing.view");
  const sp = await searchParams;
  const { now, book, quotes, tenants, editing } = await loadPricing(one(sp.quote));
  const canSeeMargin = can(user, "pricing.margin");
  const parsed = editing ? quoteConfigSchema.safeParse(editing.config) : null;
  const initial = parsed?.success ? parsed.data : defaultQuoteConfig();

  const rows: PriceRow[] = [
    ...PRICE_ITEMS.map((i) => ({
      key: i.key,
      group: i.group,
      label: i.label,
      unit: i.note ?? i.unit,
      defaultPrice: i.price,
      defaultCost: i.cost,
      price: book[i.key]?.price ?? i.price,
      cost: book[i.key]?.cost ?? i.cost,
      overridden: !!book[i.key],
    })),
    ...TOOLS.filter((t) => CATEGORIES.find((c) => c.key === t.category)?.priced).map((t) => ({
      key: `tool.${t.key}`,
      group: `Tools · ${CATEGORIES.find((c) => c.key === t.category)?.label}`,
      label: toolLabel(t),
      unit: UNIT_LABEL[t.price.unit],
      defaultPrice: t.price.amount,
      price: book[`tool.${t.key}`]?.price ?? t.price.amount,
      overridden: !!book[`tool.${t.key}`],
      basis: t.price.basis,
    })),
  ];
  const pipeline = quotes.filter((q) => q.status === "SENT").reduce((s, q) => s + ((q.totals as unknown as QuoteResult).monthlyNet ?? 0), 0);
  const won = quotes.filter((q) => q.status === "ACCEPTED").reduce((s, q) => s + ((q.totals as unknown as QuoteResult).monthlyNet ?? 0), 0);

  return (
    <div className="flex flex-col gap-6">
      <Configurator
        key={editing?.id ?? "new"}
        priceBook={book}
        canSeeMargin={canSeeMargin}
        tenants={tenants}
        initial={initial}
        quoteId={editing?.id}
        quoteReference={editing?.reference}
        quoteTenantId={editing?.tenantId}
      />

      <div className="no-print grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-3">
          <CardHeader>
            <CardTitle className="text-base">Quotes</CardTitle>
            <CardDescription>
              Open pipeline {formatMoney(pipeline, "USD", 1, { decimals: 0 })}/mo · won {formatMoney(won, "USD", 1, { decimals: 0 })}/mo (USD, at list).
            </CardDescription>
          </CardHeader>
          <CardContent>
            {quotes.length === 0 ? (
              <EmptyState icon={FileText} title="No quotes yet" description="Build a stack above and save it as a quote." />
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Quote</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Monthly</TableHead>
                      <TableHead className="text-right">Year 1</TableHead>
                      <TableHead className="text-right">Updated</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {quotes.map((q) => {
                      const totals = q.totals as unknown as QuoteResult;
                      return (
                        <TableRow key={q.id}>
                          <TableCell>
                            <Link href={`/pricing/quotes/${q.id}`} className="text-sm font-medium hover:underline">{q.clientName}</Link>
                            <p className="font-mono text-[11px] text-muted-foreground">{q.reference}{q.tenant ? ` · ${q.tenant.name}` : ""}</p>
                          </TableCell>
                          <TableCell><Badge variant={QUOTE_VARIANT[q.status]}>{q.status.toLowerCase()}</Badge></TableCell>
                          <TableCell className="text-right tabular-nums">{formatMoney(totals.monthlyNet, q.currency, totals.fxRate, { decimals: 0 })}</TableCell>
                          <TableCell className="text-right tabular-nums">{formatMoney(totals.year1Total, q.currency, totals.fxRate, { decimals: 0 })}</TableCell>
                          <TableCell className="text-right text-xs text-muted-foreground">{formatRelative(q.updatedAt, now)}</TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Price book</CardTitle>
            <CardDescription>
              Your rates. Defaults are indicative — tool prices are vendor list prices or estimates for quote-only vendors.{" "}
              {can(user, "pricing.manage") ? "Edits apply to every new calculation." : "Only platform admins can edit."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <PriceBookEditor rows={rows} canEdit={can(user, "pricing.manage")} showCost={canSeeMargin} />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
