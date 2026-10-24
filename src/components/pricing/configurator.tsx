"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { AlertTriangle, Check, CircleCheck, CircleDashed, Cloud, HardDrive, Loader2, Printer, Save, Sparkles, X } from "lucide-react";
import { toast } from "sonner";

import { saveQuoteAction } from "@/app/(app)/pricing/actions";
import { CATEGORIES, TOOLS, UNIT_LABEL } from "@/lib/integrations/catalog";
import { CONTROLS } from "@/lib/endpoints/controls";
import { PLANS, PLAN_FEATURE_LABEL, PLAN_KEYS, type PlanFeature, type PlanKey } from "@/lib/plans";
import { MODEL_PRICING } from "@/lib/ai/catalog";
import { CURRENCIES, type PriceBook } from "@/lib/pricing/catalog";
import { calculateQuote, comparePlans, formatMoney, toolLabel, toolMonthlyPrice, type QuoteConfig, type QuoteResult } from "@/lib/pricing/calculator";
import { useChartTokens } from "@/lib/chart-theme";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { TenantSelect } from "@/components/shared/tenant-select";

const PRESETS = [
  { label: "Small office", workstations: 20, servers: 2, users: 20, logGbPerDay: 1 },
  { label: "SMB", workstations: 100, servers: 10, users: 100, logGbPerDay: 5 },
  { label: "Mid-market", workstations: 450, servers: 50, users: 500, logGbPerDay: 25 },
  { label: "Enterprise", workstations: 1800, servers: 200, users: 2000, logGbPerDay: 120 },
];

const KIND_LABEL = { service: "Managed service", license: "Tool licences", ai: "AI first response", services: "Professional services" } as const;
const KINDS = ["service", "license", "ai", "services"] as const;

interface Props {
  priceBook: PriceBook;
  canSeeMargin: boolean;
  tenants: Array<{ id: string; name: string }>;
  initial: QuoteConfig;
  quoteId?: string;
  quoteReference?: string;
  quoteTenantId?: string | null;
}

function NumberField({ label, value, onChange, min = 0, step = 1, suffix }: { label: string; value: number; onChange: (n: number) => void; min?: number; step?: number; suffix?: string }) {
  return (
    <div className="grid gap-1.5">
      <Label className="text-xs">{label}</Label>
      <div className="relative">
        <Input type="number" min={min} step={step} value={Number.isFinite(value) ? value : 0} onChange={(e) => onChange(Math.max(min, Number(e.target.value) || 0))} className={cn("tabular", suffix && "pr-12")} />
        {suffix && <span className="pointer-events-none absolute inset-y-0 right-3 flex items-center text-xs text-muted-foreground">{suffix}</span>}
      </div>
    </div>
  );
}

// Part-to-whole of the monthly net, by kind: a 2px-gapped stacked bar with a
// legend that carries every value (identity is never color alone).
function CompositionBar({ result, money }: { result: QuoteResult; money: (usd: number) => string }) {
  const t = useChartTokens();
  const parts = KINDS.map((k, i) => ({ kind: k, value: result.lines.filter((l) => l.kind === k).reduce((s, l) => s + l.monthly, 0), color: t.series[i] })).filter((p) => p.value > 0);
  const total = parts.reduce((s, p) => s + p.value, 0) || 1;
  return (
    <div className="flex flex-col gap-2">
      <div className="flex h-3 gap-[2px] overflow-hidden rounded-full" role="img" aria-label="Monthly cost by component">
        {parts.map((p) => (
          <div key={p.kind} className="h-full first:rounded-l-full last:rounded-r-full" style={{ width: `${(p.value / total) * 100}%`, background: p.color }} title={`${KIND_LABEL[p.kind]}: ${money(p.value)}`} />
        ))}
      </div>
      <ul className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
        {parts.map((p) => (
          <li key={p.kind} className="flex items-center justify-between gap-2">
            <span className="flex items-center gap-1.5 text-muted-foreground">
              <span className="size-2 rounded-full" style={{ background: p.color }} />
              {KIND_LABEL[p.kind]}
            </span>
            <span className="tabular text-foreground">{money(p.value)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function Configurator({ priceBook, canSeeMargin, tenants, initial, quoteId, quoteReference, quoteTenantId }: Props) {
  const router = useRouter();
  const [cfg, setCfg] = React.useState<QuoteConfig>(initial);
  const [tenantId, setTenantId] = React.useState(quoteTenantId ?? "none");
  const [compareCategory, setCompareCategory] = React.useState("edr");
  const result = React.useMemo(() => calculateQuote(cfg, priceBook), [cfg, priceBook]);
  const plans = React.useMemo(() => comparePlans(cfg, priceBook), [cfg, priceBook]);
  const money = React.useCallback((usd: number, decimals?: number) => formatMoney(usd, cfg.commercial.currency, cfg.commercial.fxRate, { decimals }), [cfg.commercial.currency, cfg.commercial.fxRate]);

  const set = <K extends keyof QuoteConfig>(key: K, value: Partial<QuoteConfig[K]>) =>
    setCfg((c) => ({ ...c, [key]: typeof value === "object" && !Array.isArray(value) ? { ...(c[key] as object), ...value } : value }));
  const setTool = (category: string, tool: string) => setCfg((c) => ({ ...c, tools: { ...c.tools, [category]: tool } }));

  const save = useMutation({
    mutationFn: () => saveQuoteAction(cfg, { quoteId, tenantId: tenantId === "none" ? null : tenantId }),
    onSuccess: (r) => {
      toast.success(`Quote ${r.reference} saved`);
      router.push(`/pricing/quotes/${r.id}`);
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Save failed"),
  });

  const endpoints = cfg.profile.workstations + cfg.profile.servers;
  const pricedCategories = CATEGORIES.filter((c) => c.priced);

  const summary = (
    <div className="flex flex-col gap-4 lg:sticky lg:top-20">
      <Card className="surface-glow overflow-hidden">
        <CardHeader className="pb-2">
          <CardDescription>{quoteReference ? `Quote ${quoteReference}` : "Estimate"} · {PLANS[cfg.plan].name} · {endpoints.toLocaleString()} endpoints</CardDescription>
          <p className="text-4xl font-semibold tracking-tight">{money(result.monthlyNet, 0)}<span className="text-base font-normal text-muted-foreground"> / month</span></p>
          <p className="text-xs text-muted-foreground">
            {money(result.perEndpointMonthly)} per endpoint · {money(result.perUserMonthly)} per user · {cfg.commercial.term === "monthly" ? "month-to-month" : cfg.commercial.term === "annual" ? "annual term" : "3-year term"}
          </p>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <CompositionBar result={result} money={(v) => money(v, 0)} />
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted-foreground">Annual recurring</dt>
            <dd className="text-right font-medium tabular">{money(result.annualRecurring, 0)}</dd>
            <dt className="text-muted-foreground">One-time (onboarding{cfg.ai.mode === "local" ? ", AI hardware" : ""})</dt>
            <dd className="text-right font-medium tabular">{money(result.oneTime, 0)}</dd>
            {result.amcAnnual > 0 && (
              <>
                <dt className="text-muted-foreground">Annual maintenance (AMC, from year 2)</dt>
                <dd className="text-right font-medium tabular">{money(result.amcAnnual, 0)} <span className="text-xs text-muted-foreground">({money(result.amcMonthly, 0)}/mo)</span></dd>
              </>
            )}
            {result.tax > 0 && (
              <>
                <dt className="text-muted-foreground">Tax ({cfg.commercial.taxPct}%)</dt>
                <dd className="text-right tabular">{money(result.tax, 0)}</dd>
              </>
            )}
            <dt className="font-medium">Year 1 total</dt>
            <dd className="text-right text-base font-semibold tabular">{money(result.year1Total, 0)}</dd>
            <dt className="text-muted-foreground">3-year total cost</dt>
            <dd className="text-right tabular">{money(result.threeYearTotal, 0)}</dd>
          </dl>
          {(result.volumeDiscount > 0 || result.termDiscount > 0 || result.extraDiscount > 0) && (
            <div className="rounded-md bg-success/10 p-2.5 text-xs">
              <p className="font-medium text-success-ink">Discounts applied (monthly)</p>
              {result.volumeDiscount > 0 && <p className="text-muted-foreground">Volume ({result.volumeDiscountPct}% on the service fee): −{money(result.volumeDiscount)}</p>}
              {result.termDiscount > 0 && <p className="text-muted-foreground">Term ({result.termDiscountPct}%): −{money(result.termDiscount)}</p>}
              {result.extraDiscount > 0 && <p className="text-muted-foreground">Additional ({cfg.commercial.extraDiscountPct}%): −{money(result.extraDiscount)}</p>}
            </div>
          )}
          {canSeeMargin && (
            <div className="rounded-md border border-dashed p-2.5 text-xs">
              <p className="font-medium">Internal · not on the quote</p>
              <p className="text-muted-foreground">
                Year-1 cost {money(result.costYear1, 0)} · gross margin{" "}
                <span className={cn("font-semibold", (result.grossMarginPct ?? 0) < 25 ? "text-destructive" : (result.grossMarginPct ?? 0) < 40 ? "text-warning-ink" : "text-success-ink")}>
                  {result.grossMarginPct == null ? "—" : `${result.grossMarginPct.toFixed(1)}%`}
                </span>
              </p>
            </div>
          )}
          {result.estimates > 0 && (
            <p className="flex items-start gap-1.5 text-[11px] text-muted-foreground">
              <AlertTriangle className="mt-0.5 size-3 shrink-0 text-warning-ink" />
              {result.estimates} line{result.estimates === 1 ? " is" : "s are"} priced on estimates. Confirm vendor quotes before sending.
            </p>
          )}
          <div className="grid gap-2">
            {!quoteId && <TenantSelect tenants={tenants} value={tenantId} onChange={setTenantId} />}
            <div className="flex gap-2">
              <Button className="flex-1" onClick={() => save.mutate()} disabled={save.isPending || !cfg.clientName.trim()}>
                {save.isPending ? <Loader2 className="animate-spin" /> : <Save />}
                {quoteId ? "Update quote" : "Save quote"}
              </Button>
              <Button variant="outline" onClick={() => window.print()} aria-label="Print">
                <Printer />
              </Button>
            </div>
            {!cfg.clientName.trim() && <p className="text-[11px] text-muted-foreground">Add the client&apos;s name to save.</p>}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Protection coverage of this stack</CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="grid grid-cols-1 gap-1 text-xs">
            {result.coverage.map((c) => {
              const info = CONTROLS.find((x) => x.key === c.control)!;
              return (
                <li key={c.control} className="flex items-center gap-1.5" title={c.by.join(", ") || "Not covered"}>
                  {c.covered ? <CircleCheck className="size-3.5 text-success-ink" /> : c.essential ? <X className="size-3.5 text-destructive" /> : <CircleDashed className="size-3.5 text-muted-foreground" />}
                  <span className={cn(!c.covered && c.essential && "font-medium text-destructive")}>{info.label}</span>
                  {c.essential && <span className="text-[10px] uppercase text-muted-foreground">essential</span>}
                  <span className="ml-auto truncate text-muted-foreground">{c.by[0] ?? ""}</span>
                </li>
              );
            })}
          </ul>
          {result.gaps.length > 0 && <p className="mt-2 text-xs text-destructive">Essential gaps: add tools covering {result.gaps.map((g) => CONTROLS.find((c) => c.key === g)?.short).join(", ")}.</p>}
        </CardContent>
      </Card>
    </div>
  );

  return (
    <Tabs defaultValue="build" className="gap-4">
      <TabsList className="no-print">
        <TabsTrigger value="build">Build</TabsTrigger>
        <TabsTrigger value="compare">Compare</TabsTrigger>
        <TabsTrigger value="breakdown">Line items</TabsTrigger>
      </TabsList>

      <div className="grid gap-4 lg:grid-cols-[1fr_22rem]">
        <div className="min-w-0">
          <TabsContent value="build" className="flex flex-col gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">1 · Client profile</CardTitle>
                <CardDescription>Size drives every per-unit price and the volume discount.</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-4">
                <div className="grid gap-1.5">
                  <Label className="text-xs">Client name</Label>
                  <Input value={cfg.clientName} onChange={(e) => set("clientName", e.target.value as never)} placeholder="e.g. Northwind Health" />
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {PRESETS.map((p) => (
                    <Button key={p.label} size="sm" variant="outline" className="h-7 text-xs" onClick={() => set("profile", { workstations: p.workstations, servers: p.servers, users: p.users, logGbPerDay: p.logGbPerDay })}>
                      {p.label}
                    </Button>
                  ))}
                </div>
                <div className="grid gap-3 sm:grid-cols-4">
                  <NumberField label="Workstations & laptops" value={cfg.profile.workstations} onChange={(n) => set("profile", { workstations: n })} />
                  <NumberField label="Servers" value={cfg.profile.servers} onChange={(n) => set("profile", { servers: n })} />
                  <NumberField label="Users / mailboxes" value={cfg.profile.users} onChange={(n) => set("profile", { users: n })} />
                  <NumberField label="Log volume" value={cfg.profile.logGbPerDay} onChange={(n) => set("profile", { logGbPerDay: n })} step={0.5} suffix="GB/day" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">2 · Service plan</CardTitle>
              </CardHeader>
              <CardContent className="grid gap-3 md:grid-cols-3">
                {plans.map(({ plan, result: r }) => {
                  const p = PLANS[plan];
                  const active = cfg.plan === plan;
                  return (
                    <button
                      key={plan}
                      type="button"
                      onClick={() => set("plan", plan as never)}
                      className={cn("flex flex-col gap-2 rounded-lg border p-4 text-left transition-colors hover:border-primary/50", active && "border-primary bg-primary/5 ring-1 ring-primary")}
                    >
                      <div className="flex items-center justify-between">
                        <p className="text-sm font-semibold">{p.name}</p>
                        {active && <Check className="size-4 text-primary" />}
                      </div>
                      <p className="text-xs text-muted-foreground">{p.tagline}</p>
                      <p className="text-lg font-semibold">{money(r.monthlyNet, 0)}<span className="text-xs font-normal text-muted-foreground"> /mo</span></p>
                      <ul className="space-y-0.5 text-[11px] text-muted-foreground">
                        <li>{p.coverage} analysts · critical ack ≤ {p.ackMinutes.CRITICAL} min</li>
                        <li>Containment: {String(p.features.autoContainment)}</li>
                        <li>Hunting: {p.features.threatHunting === false ? "—" : String(p.features.threatHunting)} · IR {p.irRetainerHours} h/yr</li>
                      </ul>
                    </button>
                  );
                })}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">3 · Protection stack</CardTitle>
                <CardDescription>One tool per layer — or the client&apos;s existing licence. Prices are indicative list prices or marked estimates; your price book overrides them.</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col divide-y">
                {pricedCategories.map((c) => {
                  const choice = cfg.tools[c.key] ?? "none";
                  const tool = TOOLS.find((t) => t.key === choice);
                  const price = tool ? toolMonthlyPrice(tool, cfg, priceBook) : null;
                  return (
                    <div key={c.key} className="grid gap-2 py-3 first:pt-0 last:pb-0 sm:grid-cols-[12rem_1fr_7rem] sm:items-center">
                      <div>
                        <p className="text-sm font-medium">{c.label}</p>
                        <p className="text-[11px] text-muted-foreground">{c.description}</p>
                      </div>
                      <NativeSelect value={choice} onChange={(e) => setTool(c.key, e.target.value)} aria-label={c.label}>
                        <option value="none">Not included</option>
                        <option value="byo">Client already has one</option>
                        {TOOLS.filter((t) => t.category === c.key).map((t) => {
                          const tp = toolMonthlyPrice(t, cfg, priceBook);
                          return (
                            <option key={t.key} value={t.key}>
                              {toolLabel(t)} — {tp.unitPrice ? `${money(tp.unitPrice)} ${UNIT_LABEL[t.price.unit]}` : "no licence fee"}
                              {t.price.basis === "estimate" ? " (est.)" : ""}
                            </option>
                          );
                        })}
                      </NativeSelect>
                      <p className="text-right text-sm tabular">{price ? money(price.monthly, 0) : "—"}</p>
                    </div>
                  );
                })}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">4 · AI first response</CardTitle>
                <CardDescription>AI agents triage every alert and start containment; your analysts take it from there.</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-4">
                <div className="grid gap-2 sm:grid-cols-3">
                  {(
                    [
                      { key: "none", label: "No AI", icon: X, note: "Analysts only" },
                      { key: "cloud", label: "Cloud (Claude)", icon: Cloud, note: "Pay per alert, no hardware" },
                      { key: "local", label: "Local / offline", icon: HardDrive, note: "On-prem GPU, data never leaves" },
                    ] as const
                  ).map((m) => (
                    <button
                      key={m.key}
                      type="button"
                      onClick={() => set("ai", { mode: m.key })}
                      className={cn("flex items-start gap-2 rounded-lg border p-3 text-left hover:border-primary/50", cfg.ai.mode === m.key && "border-primary bg-primary/5 ring-1 ring-primary")}
                    >
                      <m.icon className="mt-0.5 size-4 text-muted-foreground" />
                      <span>
                        <span className="block text-sm font-medium">{m.label}</span>
                        <span className="block text-[11px] text-muted-foreground">{m.note}</span>
                      </span>
                    </button>
                  ))}
                </div>
                {cfg.ai.mode === "cloud" && (
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="grid gap-1.5">
                      <Label className="text-xs">Model</Label>
                      <NativeSelect value={cfg.ai.model} onChange={(e) => set("ai", { model: e.target.value })}>
                        {Object.entries(MODEL_PRICING).map(([m, p]) => (
                          <option key={m} value={m}>{m} — ${p.input}/${p.output} per M tokens</option>
                        ))}
                      </NativeSelect>
                    </div>
                    {result.aiUsage && (
                      <p className="self-end text-xs text-muted-foreground">
                        ~{result.aiUsage.alertsPerMonth.toLocaleString()} AI triages/month · {(result.aiUsage.tokensPerMonth / 1_000_000).toFixed(1)}M tokens · model cost ≈ {money(result.aiUsage.modelCostMonthly)}/month
                      </p>
                    )}
                  </div>
                )}
                {cfg.ai.mode === "local" && (
                  <div className="grid gap-1.5 sm:max-w-sm">
                    <Label className="text-xs">Hardware</Label>
                    <NativeSelect value={cfg.ai.hardware} onChange={(e) => set("ai", { hardware: e.target.value as QuoteConfig["ai"]["hardware"] })}>
                      <option value="workstation">GPU workstation — up to ~300 endpoints</option>
                      <option value="server">GPU server — up to ~2,000 endpoints</option>
                      <option value="cluster">Inference cluster — large or multi-client estates</option>
                    </NativeSelect>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">5 · Add-on services</CardTitle>
              </CardHeader>
              <CardContent className="grid gap-4 sm:grid-cols-3">
                <NumberField label="Extra IR hours / year" value={cfg.services.irExtraHours} onChange={(n) => set("services", { irExtraHours: n })} />
                <NumberField label="Penetration tests / year" value={cfg.services.pentests} onChange={(n) => set("services", { pentests: n })} />
                <NumberField label="Awareness workshops / year" value={cfg.services.trainingSessions} onChange={(n) => set("services", { trainingSessions: n })} />
                {(
                  [
                    { key: "compliance", label: "Compliance evidence packs", included: PLANS[cfg.plan].features.compliance !== false },
                    { key: "dedicatedAnalyst", label: "Named lead analyst", included: PLANS[cfg.plan].features.dedicatedAnalyst === true },
                    { key: "premiumSupport", label: "Premium support", included: false },
                  ] as const
                ).map((s) => (
                  <label key={s.key} className="flex items-center gap-2 rounded-lg border p-3 text-sm">
                    <Switch checked={s.included || cfg.services[s.key]} disabled={s.included} onCheckedChange={(v) => set("services", { [s.key]: v })} />
                    <span>
                      {s.label}
                      {s.included && <span className="block text-[11px] text-muted-foreground">Included in plan</span>}
                    </span>
                  </label>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">6 · Commercial terms</CardTitle>
              </CardHeader>
              <CardContent className="grid gap-4 sm:grid-cols-5">
                <div className="grid gap-1.5 sm:col-span-2">
                  <Label className="text-xs">Term</Label>
                  <NativeSelect value={cfg.commercial.term} onChange={(e) => set("commercial", { term: e.target.value as QuoteConfig["commercial"]["term"] })}>
                    <option value="monthly">Month-to-month</option>
                    <option value="annual">Annual (prepaid)</option>
                    <option value="3year">3-year term</option>
                  </NativeSelect>
                </div>
                <div className="grid gap-1.5">
                  <Label className="text-xs">Currency</Label>
                  <NativeSelect value={cfg.commercial.currency} onChange={(e) => set("commercial", { currency: e.target.value, fxRate: CURRENCIES[e.target.value]?.rate ?? 1 })}>
                    {Object.keys(CURRENCIES).map((c) => (
                      <option key={c} value={c}>{c}</option>
                    ))}
                  </NativeSelect>
                </div>
                <NumberField label={`Rate (1 USD = ${cfg.commercial.currency})`} value={cfg.commercial.fxRate} onChange={(n) => set("commercial", { fxRate: n || 1 })} step={0.01} />
                <NumberField label="Tax (GST/VAT)" value={cfg.commercial.taxPct} onChange={(n) => set("commercial", { taxPct: Math.min(40, n) })} step={0.5} suffix="%" />
                <NumberField label="Additional discount" value={cfg.commercial.extraDiscountPct} onChange={(n) => set("commercial", { extraDiscountPct: Math.min(50, n) })} step={0.5} suffix="%" />
                <p className="text-[11px] text-muted-foreground sm:col-span-4 sm:self-end">Exchange rates are indicative defaults — set today&apos;s rate before sending. Term discounts apply to your services, not resold licences.</p>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="compare" className="flex flex-col gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Plans side by side</CardTitle>
                <CardDescription>The same client and stack on each plan.</CardDescription>
              </CardHeader>
              <CardContent className="overflow-x-auto">
                <table className="w-full min-w-[36rem] text-sm">
                  <thead>
                    <tr className="border-b text-left">
                      <th className="py-2 pr-3 font-medium text-muted-foreground" />
                      {plans.map(({ plan }) => (
                        <th key={plan} className="px-3 py-2 font-semibold">
                          {PLANS[plan].name}
                          {cfg.plan === plan && <Badge variant="default" className="ml-1.5">selected</Badge>}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {(
                      [
                        ["Monthly", (r: QuoteResult) => money(r.monthlyNet, 0)],
                        ["Year 1 total", (r: QuoteResult) => money(r.year1Total, 0)],
                        ["3-year total", (r: QuoteResult) => money(r.threeYearTotal, 0)],
                        ["Per endpoint / month", (r: QuoteResult) => money(r.perEndpointMonthly)],
                      ] as const
                    ).map(([label, fn]) => (
                      <tr key={label}>
                        <td className="py-2 pr-3 text-muted-foreground">{label}</td>
                        {plans.map(({ plan, result: r }) => (
                          <td key={plan} className="px-3 py-2 tabular">{fn(r)}</td>
                        ))}
                      </tr>
                    ))}
                    {(["CRITICAL", "HIGH", "MEDIUM"] as const).map((s) => (
                      <tr key={s}>
                        <td className="py-2 pr-3 text-muted-foreground">Acknowledge {s.toLowerCase()}</td>
                        {PLAN_KEYS.map((plan) => (
                          <td key={plan} className="px-3 py-2 tabular">≤ {PLANS[plan].ackMinutes[s]} min</td>
                        ))}
                      </tr>
                    ))}
                    {(Object.keys(PLAN_FEATURE_LABEL) as PlanFeature[]).map((f) => (
                      <tr key={f}>
                        <td className="py-2 pr-3 text-muted-foreground">{PLAN_FEATURE_LABEL[f]}</td>
                        {PLAN_KEYS.map((plan: PlanKey) => {
                          const v = PLANS[plan].features[f];
                          return (
                            <td key={plan} className="px-3 py-2">
                              {v === true ? <Check className="size-4 text-success-ink" aria-label="Included" /> : v === false ? <span className="text-muted-foreground">—</span> : <span className="text-xs">{v}</span>}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                    <tr>
                      <td />
                      {PLAN_KEYS.map((plan) => (
                        <td key={plan} className="px-3 py-3">
                          <Button size="sm" variant={cfg.plan === plan ? "default" : "outline"} onClick={() => set("plan", plan as never)}>
                            {cfg.plan === plan ? "Selected" : "Choose"}
                          </Button>
                        </td>
                      ))}
                    </tr>
                  </tbody>
                </table>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Tools compared</CardTitle>
                <CardDescription>Capabilities and cost for this client&apos;s size. HELIOS can receive alerts from tools marked &quot;alerts&quot; and drive their response actions through a connector.</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-3">
                <div className="flex flex-wrap gap-1.5">
                  {pricedCategories.map((c) => (
                    <button key={c.key} type="button" onClick={() => setCompareCategory(c.key)} className={cn("rounded-full border px-3 py-1 text-xs font-medium hover:bg-accent", compareCategory === c.key && "border-primary bg-primary text-primary-foreground hover:bg-primary/90")}>
                      {c.label}
                    </button>
                  ))}
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[44rem] text-sm">
                    <thead>
                      <tr className="border-b text-left text-xs text-muted-foreground">
                        <th className="py-2 pr-3 font-medium">Tool</th>
                        <th className="px-2 py-2 font-medium">Unit price</th>
                        <th className="px-2 py-2 text-right font-medium">This client / month</th>
                        <th className="px-2 py-2 font-medium">Covers</th>
                        <th className="px-2 py-2 font-medium">Platforms</th>
                        <th className="px-2 py-2 font-medium">HELIOS</th>
                        <th className="py-2" />
                      </tr>
                    </thead>
                    <tbody className="divide-y">
                      {TOOLS.filter((t) => t.category === compareCategory).map((t) => {
                        const p = toolMonthlyPrice(t, cfg, priceBook);
                        const chosen = cfg.tools[t.category] === t.key;
                        return (
                          <tr key={t.key} className={cn(chosen && "bg-primary/5")}>
                            <td className="py-2 pr-3">
                              <p className="font-medium">{toolLabel(t)}</p>
                              <p className="text-[11px] text-muted-foreground">{t.deployment}{t.offlineCapable ? " · works offline" : ""}</p>
                            </td>
                            <td className="px-2 py-2 text-xs">
                              {p.unitPrice ? `${money(p.unitPrice)} ${UNIT_LABEL[t.price.unit]}` : "No licence fee"}
                              <p className="text-[11px] text-muted-foreground">{t.price.basis === "estimate" ? "estimate" : t.price.basis === "list" ? "list price" : "included"}{t.price.note ? ` · ${t.price.note}` : ""}</p>
                            </td>
                            <td className="px-2 py-2 text-right tabular">{money(p.monthly, 0)}</td>
                            <td className="px-2 py-2">
                              <div className="flex flex-wrap gap-1">
                                {t.controls.length ? t.controls.map((c) => <Badge key={c} variant="outline" className="font-mono text-[10px] uppercase">{CONTROLS.find((x) => x.key === c)?.short}</Badge>) : <span className="text-xs text-muted-foreground">—</span>}
                              </div>
                            </td>
                            <td className="px-2 py-2 text-xs text-muted-foreground">{t.platforms.join(", ")}</td>
                            <td className="px-2 py-2">
                              <div className="flex flex-wrap gap-1">
                                {t.ingest && <Badge variant="soft">alerts</Badge>}
                                {t.actions.length > 0 && <Badge variant="soft">{t.actions.length} actions</Badge>}
                              </div>
                            </td>
                            <td className="py-2 text-right">
                              <Button size="sm" variant={chosen ? "default" : "outline"} className="h-7" onClick={() => setTool(t.category, t.key)}>
                                {chosen ? "In stack" : "Use"}
                              </Button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base"><Sparkles className="size-4" /> AI: cloud vs local over 3 years</CardTitle>
                <CardDescription>Same client, same plan — only the AI option changes.</CardDescription>
              </CardHeader>
              <CardContent className="overflow-x-auto">
                <table className="w-full min-w-[32rem] text-sm">
                  <thead>
                    <tr className="border-b text-left text-xs text-muted-foreground">
                      <th className="py-2 pr-3 font-medium">Option</th>
                      <th className="px-2 py-2 text-right font-medium">Monthly</th>
                      <th className="px-2 py-2 text-right font-medium">One-time</th>
                      <th className="px-2 py-2 text-right font-medium">3-year total</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {[
                      ...Object.keys(MODEL_PRICING).map((m) => ({ label: `Cloud · ${m}`, ai: { ...cfg.ai, mode: "cloud" as const, model: m } })),
                      ...(["workstation", "server", "cluster"] as const).map((h) => ({ label: `Local · ${h}`, ai: { ...cfg.ai, mode: "local" as const, hardware: h } })),
                      { label: "No AI", ai: { ...cfg.ai, mode: "none" as const } },
                    ].map((o) => {
                      const r = calculateQuote({ ...cfg, ai: o.ai }, priceBook);
                      const current = o.ai.mode === cfg.ai.mode && (o.ai.mode === "none" || (o.ai.mode === "cloud" ? o.ai.model === cfg.ai.model : o.ai.hardware === cfg.ai.hardware));
                      return (
                        <tr key={o.label} className={cn(current && "bg-primary/5")}>
                          <td className="py-2 pr-3">
                            <button type="button" className="text-left hover:underline" onClick={() => set("ai", o.ai)}>{o.label}</button>
                            {current && <Badge variant="default" className="ml-1.5">selected</Badge>}
                          </td>
                          <td className="px-2 py-2 text-right tabular">{money(r.monthlyNet, 0)}</td>
                          <td className="px-2 py-2 text-right tabular">{money(r.oneTime, 0)}</td>
                          <td className="px-2 py-2 text-right tabular">{money(r.threeYearTotal, 0)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="breakdown">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Line items</CardTitle>
                <CardDescription>Before term and volume discounts.</CardDescription>
              </CardHeader>
              <CardContent className="overflow-x-auto">
                <table className="w-full min-w-[36rem] text-sm">
                  <thead>
                    <tr className="border-b text-left text-xs text-muted-foreground">
                      <th className="py-2 pr-3 font-medium">Item</th>
                      <th className="px-2 py-2 font-medium">Detail</th>
                      <th className="px-2 py-2 text-right font-medium">Monthly</th>
                      <th className="px-2 py-2 text-right font-medium">One-time</th>
                      {canSeeMargin && <th className="px-2 py-2 text-right font-medium">Cost / mo</th>}
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {result.lines.map((l) => (
                      <tr key={l.key}>
                        <td className="py-2 pr-3">
                          {l.label}
                          <p className="text-[11px] text-muted-foreground">{KIND_LABEL[l.kind]}{l.basis === "estimate" ? " · estimate" : ""}</p>
                        </td>
                        <td className="px-2 py-2 text-xs text-muted-foreground">{l.detail}</td>
                        <td className="px-2 py-2 text-right tabular">{l.monthly ? money(l.monthly) : "—"}</td>
                        <td className="px-2 py-2 text-right tabular">{l.oneTime ? money(l.oneTime, 0) : "—"}</td>
                        {canSeeMargin && <td className="px-2 py-2 text-right tabular text-muted-foreground">{l.costMonthly ? money(l.costMonthly) : "—"}</td>}
                      </tr>
                    ))}
                    <tr className="font-medium">
                      <td className="py-2 pr-3" colSpan={2}>Total before discounts</td>
                      <td className="px-2 py-2 text-right tabular">{money(result.monthlyGross)}</td>
                      <td className="px-2 py-2 text-right tabular">{money(result.oneTime, 0)}</td>
                      {canSeeMargin && <td className="px-2 py-2 text-right tabular">{money(result.costMonthly)}</td>}
                    </tr>
                  </tbody>
                </table>
              </CardContent>
            </Card>
          </TabsContent>
        </div>
        {summary}
      </div>
    </Tabs>
  );
}
