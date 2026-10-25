import Link from "next/link";
import { FileText } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { listPlans } from "@/lib/service-plans";
import { listCatalogTools } from "@/lib/integrations/tools";
import { PRICE_ITEMS, ITEM_UNIT_LABEL } from "@/lib/pricing/items";
import { defaultQuoteConfig, formatMoney, quoteConfigSchema, type QuoteResult } from "@/lib/pricing/calculator";
import { loadModelPrices, loadPricingContext } from "@/lib/pricing/service";
import { clientStackConfig } from "@/lib/pricing/client-stack";
import { mixFromCounts, mixServers, mixWorkstations } from "@/lib/pricing/endpoint-mix";
import { formatRelative } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { EmptyState } from "@/components/shared/empty-state";
import { Configurator, type ClientSizing } from "@/components/pricing/configurator";
import { PriceBookEditor, type PriceRow } from "@/components/pricing/price-book";
import { PlansEditor } from "@/components/pricing/plans-editor";
import { CurrencyEditor, ModelPriceEditor, ToolCatalogEditor, VolumeEditor } from "@/components/pricing/reference-editors";

const QUOTE_VARIANT = { DRAFT: "outline", SENT: "info", ACCEPTED: "success", LOST: "soft" } as const;

function one(v: string | string[] | undefined) {
  return Array.isArray(v) ? v[0] : v;
}

// Client sizes for "size from an existing client": licensed counts, or the
// inventory when it's larger, with the inventory's endpoint mix by OS.
async function clientSizing(): Promise<ClientSizing[]> {
  const [tenants, inventory] = await Promise.all([
    db.tenant.findMany({ where: { status: { not: "SUSPENDED" } }, select: { id: true, name: true, endpointsLicensed: true, usersLicensed: true }, orderBy: { name: "asc" } }),
    db.endpoint.groupBy({ by: ["tenantId", "os"], where: { tenantId: { not: null } }, _count: { _all: true } }),
  ]);
  return tenants.map((t) => {
    const rows = inventory.filter((r) => r.tenantId === t.id).map((r) => ({ os: r.os, count: r._count._all }));
    const mix = rows.length ? mixFromCounts(rows, t.endpointsLicensed) : null;
    const servers = mix ? mixServers(mix) : 0;
    return { id: t.id, name: t.name, endpoints: Math.max(t.endpointsLicensed, mix ? mixWorkstations(mix) + servers : 0), servers, users: t.usersLicensed, mix };
  });
}

async function loadPricing(editId: string | undefined, setup: boolean) {
  const now = new Date();
  const [ctx, quotes, tenants, editing, setupData] = await Promise.all([
    loadPricingContext(),
    db.quote.findMany({ orderBy: { updatedAt: "desc" }, take: 30, include: { createdBy: { select: { name: true } }, tenant: { select: { name: true } } } }),
    clientSizing(),
    editId ? db.quote.findUnique({ where: { id: editId } }) : Promise.resolve(null),
    setup
      ? Promise.all([
          listPlans({ includeInactive: true }),
          db.tenant.groupBy({ by: ["planId"], where: { planId: { not: null } }, _count: { _all: true } }),
          listCatalogTools({ includeInactive: true }),
          db.currency.findMany({ orderBy: { code: "asc" } }),
          loadModelPrices(),
        ])
      : Promise.resolve(null),
  ]);
  return { now, ctx, quotes, tenants, editing, setupData };
}

export default async function PricingPage({ searchParams }: PageProps<"/pricing">) {
  const user = await pageGuard("pricing.view");
  const sp = await searchParams;
  const canManage = can(user, "pricing.manage");
  const canSeeMargin = can(user, "pricing.margin");
  const { now, ctx, quotes, tenants, editing, setupData } = await loadPricing(one(sp.quote), canManage || canSeeMargin);
  const parsed = editing ? quoteConfigSchema.safeParse(editing.config) : null;
  // ?tenant= reviews a client's current setup; ?quote= edits a saved quote.
  const clientId = editing ? undefined : one(sp.tenant);
  const client = clientId ? await clientStackConfig(clientId, ctx) : null;
  const initial = parsed?.success ? parsed.data : client?.config ?? defaultQuoteConfig(ctx);

  const rows: PriceRow[] = PRICE_ITEMS.map((i) => ({
    key: i.key,
    group: i.group,
    label: i.label,
    unit: ITEM_UNIT_LABEL[i.unit],
    note: i.note,
    hasCost: i.hasCost,
    price: ctx.book[i.key]?.price ?? null,
    cost: ctx.book[i.key]?.cost ?? null,
  }));
  const net = (q: (typeof quotes)[number]) => (q.totals as unknown as QuoteResult).monthlyNet ?? 0;
  const pipeline = quotes.filter((q) => q.status === "SENT").reduce((s, q) => s + net(q), 0);
  const won = quotes.filter((q) => q.status === "ACCEPTED").reduce((s, q) => s + net(q), 0);

  return (
    <div className="flex flex-col gap-6">
      <Configurator
        key={editing?.id ?? (client ? `tenant-${clientId}` : "new")}
        ctx={ctx}
        canSeeMargin={canSeeMargin}
        canManage={canManage}
        tenants={tenants}
        initial={initial}
        quoteId={editing?.id}
        quoteReference={editing?.reference}
        quoteTenantId={editing?.tenantId ?? (client ? clientId : undefined)}
        initialTab={one(sp.tab)}
        baselineLabel={client?.label}
      />

      <Card className="no-print">
        <CardHeader>
          <CardTitle className="text-base">Quotes</CardTitle>
          <CardDescription>
            Open pipeline {formatMoney(pipeline, "USD", 1, { decimals: 0 })}/mo · won {formatMoney(won, "USD", 1, { decimals: 0 })}/mo (USD).
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
                          <p className="flex flex-wrap items-center gap-1.5 font-mono text-[11px] text-muted-foreground">
                            {q.reference}{q.tenant ? ` · ${q.tenant.name}` : ""}
                            {q.source === "website" && <Badge variant="info" className="font-sans text-[10px]">website request</Badge>}
                            {q.contactEmail && <span className="font-sans">{q.contactName ? `${q.contactName} · ` : ""}{q.contactEmail}</span>}
                          </p>
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

      {setupData && (
        <Card id="setup" className="no-print">
          <CardHeader>
            <CardTitle className="text-base">Pricing setup</CardTitle>
            <CardDescription>
              Your plans, rates and the tool catalog. Every quote is priced from these; nothing is pre-filled except vendor list prices and model prices with their sources.{" "}
              {canManage ? "Changes apply to new calculations; saved quotes keep their totals." : "Only platform admins can edit."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="plans" className="gap-4">
              <TabsList className="flex-wrap">
                <TabsTrigger value="plans">Service plans</TabsTrigger>
                <TabsTrigger value="book">Price book</TabsTrigger>
                <TabsTrigger value="tools">Tool catalog</TabsTrigger>
                <TabsTrigger value="volume">Volume discounts</TabsTrigger>
                <TabsTrigger value="currencies">Currencies</TabsTrigger>
                <TabsTrigger value="models">Model prices</TabsTrigger>
              </TabsList>
              <TabsContent value="plans">
                <PlansEditor plans={setupData[0]} tenantCounts={Object.fromEntries(setupData[1].map((g) => [g.planId!, g._count._all]))} canEdit={canManage} />
              </TabsContent>
              <TabsContent value="book">
                <PriceBookEditor rows={rows} canEdit={canManage} showCost={canSeeMargin} />
              </TabsContent>
              <TabsContent value="tools">
                <ToolCatalogEditor tools={setupData[2]} canEdit={canManage} />
              </TabsContent>
              <TabsContent value="volume">
                <VolumeEditor tiers={ctx.volumeTiers} canEdit={canManage} />
              </TabsContent>
              <TabsContent value="currencies">
                <CurrencyEditor currencies={setupData[3].map((c) => ({ code: c.code, symbol: c.symbol, rate: c.rate, updatedAt: c.updatedAt.toISOString() }))} canEdit={canManage} />
              </TabsContent>
              <TabsContent value="models">
                <ModelPriceEditor models={setupData[4].map((m) => ({ model: m.model, provider: m.provider, inputPer: m.inputPer, outputPer: m.outputPer, source: m.source }))} canEdit={canManage} />
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
