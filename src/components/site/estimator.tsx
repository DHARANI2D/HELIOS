"use client";

import * as React from "react";
import { useMutation } from "@tanstack/react-query";
import { AlertTriangle, Check, CircleCheck, Cloud, HardDrive, Layers, Loader2, Mail, Send, X } from "lucide-react";
import { toast } from "sonner";

import { publicAdviceAction, requestQuoteAction } from "@/app/(site)/estimate/actions";
import { CATEGORIES, UNIT_LABEL, toolLabel } from "@/lib/integrations/catalog";
import { formatMinutes } from "@/lib/plans";
import { calculateQuote, formatMoney, toolMonthlyPrice, type MissingPrice, type PricingContext, type QuoteConfig } from "@/lib/pricing/calculator";
import { EMPTY_MIX, type EndpointMix } from "@/lib/pricing/endpoint-mix";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { EndpointMixFields } from "@/components/pricing/endpoint-mix-fields";
import { StackAdvisor } from "@/components/pricing/stack-advisor";
import { UpgradeReview } from "@/components/pricing/upgrade-review";
import { EstateFields, OrgContextFields } from "@/components/pricing/estate-fields";
import { SolutionDesign } from "@/components/pricing/solution-design";
import { SurfaceCoverageCard } from "@/components/pricing/surface-coverage";
import { surfaceCoverage } from "@/lib/assets/coverage";
import type { PlatformFacts } from "@/lib/assets/designer";

interface Props {
  ctx: PricingContext;
  initial: QuoteConfig;
  brand: string;
  aiAdvisor: boolean;
  leads: boolean;
  contactEmail: string | null;
  facts: PlatformFacts | null;
}

const OTHER = "__other";

// What a visitor sees for a price the team hasn't set.
function missingLabel(m: MissingPrice) {
  switch (m.fix) {
    case "plan":
      return m.key === "plan" ? "Choose a service plan" : "Service plan";
    case "tool":
      return m.label.split(": your price")[0];
    case "ai-usage":
      return "AI usage (sized with you)";
    case "model":
      return "AI model usage";
    default:
      return m.label;
  }
}

function Field({ label, value, onChange, step = 1, suffix, hint }: { label: string; value: number; onChange: (n: number) => void; step?: number; suffix?: string; hint?: string }) {
  const id = React.useId();
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id} className="text-xs">{label}</Label>
      <div className="relative">
        <Input id={id} type="number" min={0} step={step} inputMode="decimal" value={value} onChange={(e) => onChange(Math.max(0, Number(e.target.value) || 0))} className={cn("tabular", suffix && "pr-14")} />
        {suffix && <span className="pointer-events-none absolute inset-y-0 right-3 flex items-center text-xs text-muted-foreground">{suffix}</span>}
      </div>
      {hint && <p className="text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  );
}

export function Estimator({ ctx, initial, brand, aiAdvisor, leads, contactEmail, facts }: Props) {
  const [cfg, setCfg] = React.useState<QuoteConfig>(initial);
  const [tab, setTab] = React.useState("design");
  const result = React.useMemo(() => calculateQuote(cfg, ctx), [cfg, ctx]);
  const surface = React.useMemo(() => surfaceCoverage(cfg, ctx), [cfg, ctx]);
  const money = React.useCallback((usd: number, decimals?: number) => formatMoney(usd, cfg.commercial.currency, cfg.commercial.fxRate, { decimals }), [cfg.commercial.currency, cfg.commercial.fxRate]);
  const mix = cfg.profile.mix ?? EMPTY_MIX;
  const plan = ctx.plans.find((p) => p.key === cfg.plan) ?? null;
  const priced = CATEGORIES.filter((c) => c.priced);
  const currencies = [{ code: "USD", rate: 1 }, ...ctx.currencies.filter((c) => c.code !== "USD")];
  const sized = result.endpoints > 0;
  // The estimate leaves out what nobody has priced yet.
  const onRequest = result.missing.filter((m) => m.fix !== "currency");

  const update = (patch: (c: QuoteConfig) => QuoteConfig) => setCfg((c) => patch(c));
  const setMix = (m: EndpointMix) => update((c) => ({ ...c, profile: { ...c.profile, mix: m } }));
  const setToday = (category: string, value: string) =>
    update((c) => {
      const existing = { ...c.existing };
      const tools = { ...c.tools };
      if (value === "" || value === OTHER) delete existing[category];
      else existing[category] = value;
      // Keeping what they run today is the default; their choice stands otherwise.
      const current = tools[category] ?? "none";
      if (current === "none" || current === "byo") tools[category] = value === "" ? "none" : "byo";
      return { ...c, existing, tools };
    });
  const setChoice = (category: string, value: string) => update((c) => ({ ...c, tools: { ...c.tools, [category]: value } }));
  const apply = (config: QuoteConfig) => {
    setCfg(config);
    toast.success("Estimate updated");
  };

  const summary = (
    <div className="flex flex-col gap-4 lg:sticky lg:top-20 lg:self-start">
      <Card className="surface-glow overflow-hidden">
        <CardHeader className="pb-2">
          <CardDescription>{plan?.name ?? "No plan chosen"} · {result.endpoints.toLocaleString()} endpoints · {cfg.profile.users.toLocaleString()} users</CardDescription>
          <p className="text-4xl font-semibold tracking-tight tabular">{money(result.monthlyNet, 0)}<span className="text-base font-normal text-muted-foreground"> / month</span></p>
          <p className="text-xs text-muted-foreground">
            {sized ? `${money(result.perEndpointMonthly)} per endpoint · ` : ""}
            {cfg.commercial.term === "monthly" ? "month-to-month" : cfg.commercial.term === "annual" ? "annual term" : "3-year term"} · excludes tax
          </p>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted-foreground">Annual recurring</dt>
            <dd className="text-right font-medium tabular">{money(result.annualRecurring, 0)}</dd>
            <dt className="text-muted-foreground">One-time setup</dt>
            <dd className="text-right font-medium tabular">{money(result.oneTime, 0)}</dd>
            {result.amcAnnual > 0 && (
              <>
                <dt className="text-muted-foreground">Annual maintenance (from year 2)</dt>
                <dd className="text-right font-medium tabular">{money(result.amcAnnual, 0)}</dd>
              </>
            )}
            <dt className="font-medium">Year 1 total</dt>
            <dd className="text-right text-base font-semibold tabular">{money(result.year1Total, 0)}</dd>
            <dt className="text-muted-foreground">3-year total</dt>
            <dd className="text-right tabular">{money(result.threeYearTotal, 0)}</dd>
          </dl>
          {(result.volumeDiscount > 0 || result.termDiscount > 0) && (
            <p className="rounded-md bg-success/10 p-2.5 text-xs text-success-ink">
              Includes {[result.volumeDiscount > 0 && `a ${result.volumeDiscountPct}% volume discount`, result.termDiscount > 0 && `a ${result.termDiscountPct}% term discount`].filter(Boolean).join(" and ")}: −{money(result.volumeDiscount + result.termDiscount)}/month.
            </p>
          )}
          {onRequest.length > 0 && (
            <div className="rounded-md border border-warning/40 bg-warning/10 p-2.5 text-xs" role="status">
              <p className="flex items-center gap-1.5 font-medium text-warning-ink"><AlertTriangle className="size-3.5" /> Not included yet: priced on request</p>
              <ul className="mt-1 space-y-0.5 text-muted-foreground">
                {onRequest.map((m) => <li key={m.key}>· {missingLabel(m)}</li>)}
              </ul>
            </div>
          )}
          {leads && (
            <Button asChild>
              <a href="#request"><Send /> Request a formal quote</a>
            </Button>
          )}
        </CardContent>
      </Card>

      <SurfaceCoverageCard coverage={surface} audience="public" />
    </div>
  );

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 py-10 sm:px-6">
      <div className="max-w-2xl">
        <h1 className="text-3xl font-semibold tracking-tight">Estimate your price</h1>
        <p className="mt-2 text-muted-foreground">
          Tell us about your organization, everything that needs protecting (laptops to cloud workloads, network gear, OT and apps) and the tools you use today. You get a security design, a price that updates as you type, and upgrade options. Nothing is sent to {brand} until you ask for a formal quote.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_21rem]">
        <div className="flex min-w-0 flex-col gap-4">
          <Card id="organization" className="scroll-mt-20">
            <CardHeader>
              <CardTitle className="text-base">1 · Your organization</CardTitle>
              <CardDescription>Sets which assets come first: OT and medical devices are P1 for a hospital or a factory, cloud for a cloud-first company.</CardDescription>
            </CardHeader>
            <CardContent>
              <OrgContextFields context={cfg.context} onChange={(context) => update((c) => ({ ...c, context }))} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">2 · Devices and users</CardTitle>
              <CardDescription>How many of each, including BYOD, VDI and shared machines. We check that every suggested tool runs on all of them.</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <EndpointMixFields mix={mix} onChange={setMix} />
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Users / mailboxes" value={cfg.profile.users} onChange={(n) => update((c) => ({ ...c, profile: { ...c.profile, users: Math.round(n) } }))} hint="People with an email account or sign-in" />
                <Field label="Log volume" value={cfg.profile.logGbPerDay} step={0.5} suffix="GB/day" onChange={(n) => update((c) => ({ ...c, profile: { ...c.profile, logGbPerDay: n } }))} hint="Leave at 0 if you don't know; we'll size it with you" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">3 · The rest of your attack surface</CardTitle>
              <CardDescription>Cloud, network, identities, IoT/OT and applications. Leave at 0 what you don&apos;t have.</CardDescription>
            </CardHeader>
            <CardContent>
              <EstateFields estate={cfg.profile.estate} onChange={(estate) => update((c) => ({ ...c, profile: { ...c.profile, estate } }))} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">4 · Service plan</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-3 md:grid-cols-3">
              {ctx.plans.length === 0 && <p className="text-sm text-muted-foreground md:col-span-3">Plans are being finalized; request a quote and we&apos;ll price the service for you.</p>}
              {ctx.plans.map((p) => {
                const active = cfg.plan === p.key;
                return (
                  <button key={p.key} type="button" onClick={() => update((c) => ({ ...c, plan: p.key }))} aria-pressed={active} className={cn("flex flex-col gap-1.5 rounded-lg border p-4 text-left transition-colors hover:border-primary/50", active && "border-primary bg-primary/5 ring-1 ring-primary")}>
                    <span className="flex items-center justify-between text-sm font-semibold">{p.name}{active && <Check className="size-4 text-primary" />}</span>
                    {p.tagline && <span className="text-xs text-muted-foreground">{p.tagline}</span>}
                    <span className="text-sm">{p.pricePerEndpoint == null ? <span className="text-muted-foreground">Priced on request</span> : <><span className="font-semibold tabular">{money(p.pricePerEndpoint)}</span><span className="text-xs text-muted-foreground"> / endpoint / month</span></>}</span>
                    <span className="text-[11px] text-muted-foreground">{p.coverage}{p.ackMinutes.CRITICAL != null ? ` · critical ack ≤ ${formatMinutes(p.ackMinutes.CRITICAL)}` : ""}</span>
                  </button>
                );
              })}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">5 · Security tools</CardTitle>
              <CardDescription>What you run today, and what goes in the estimate: keep your own licence, license a tool through us, or leave the layer out.</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col divide-y">
              <div className="hidden pb-2 text-[11px] font-medium text-muted-foreground sm:grid sm:grid-cols-[10rem_minmax(0,1fr)_minmax(0,1fr)_5.5rem] sm:gap-3">
                <span>Layer</span><span>You run today</span><span>In the estimate</span><span className="text-right">Monthly</span>
              </div>
              {priced.map((c) => {
                const tools = ctx.tools.filter((t) => t.category === c.key);
                const choice = cfg.tools[c.key] ?? "none";
                const today = cfg.existing[c.key] ?? (choice === "byo" ? OTHER : "");
                const tool = tools.find((t) => t.key === choice);
                const price = tool ? toolMonthlyPrice(tool, cfg).monthly : 0;
                return (
                  <div key={c.key} className="grid gap-2 py-3 first:pt-0 last:pb-0 sm:grid-cols-[10rem_minmax(0,1fr)_minmax(0,1fr)_5.5rem] sm:items-center sm:gap-3">
                    <div>
                      <p className="text-sm font-medium">{c.label}</p>
                      <p className="text-[11px] text-muted-foreground sm:hidden">{c.description}</p>
                    </div>
                    <NativeSelect value={today} onChange={(e) => setToday(c.key, e.target.value)} aria-label={`${c.label}: what you run today`} className="w-full min-w-0">
                      <option value="">Nothing</option>
                      {tools.map((t) => <option key={t.key} value={t.key}>{toolLabel(t)}</option>)}
                      <option value={OTHER}>Something else</option>
                    </NativeSelect>
                    <NativeSelect value={choice} onChange={(e) => setChoice(c.key, e.target.value)} aria-label={`${c.label}: in the estimate`} className="w-full min-w-0">
                      <option value="none">Not included</option>
                      {today && <option value="byo">Keep my own licence</option>}
                      {tools.map((t) => {
                        const p = toolMonthlyPrice(t, cfg);
                        return <option key={t.key} value={t.key}>{toolLabel(t)} · {p.unitPrice == null ? "on request" : p.unitPrice ? `${money(p.unitPrice)} ${UNIT_LABEL[t.price.unit]}` : "no licence fee"}</option>;
                      })}
                    </NativeSelect>
                    <p className="text-right text-sm tabular">{price == null ? <span className="text-xs text-warning-ink">on request</span> : price ? money(price, 0) : <span className="text-muted-foreground">—</span>}</p>
                  </div>
                );
              })}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">6 · AI first response</CardTitle>
              <CardDescription>AI agents triage every alert the moment it lands; our analysts take it from there.</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              <div className="grid gap-2 sm:grid-cols-3">
                {(
                  [
                    { key: "none", label: "No AI", icon: X, note: "Analysts only" },
                    { key: "cloud", label: "Cloud", icon: Cloud, note: "Nothing to host; usage-based" },
                    { key: "local", label: "Local / offline", icon: HardDrive, note: "Your hardware; data stays inside" },
                  ] as const
                ).map((m) => (
                  <button key={m.key} type="button" aria-pressed={cfg.ai.mode === m.key} onClick={() => update((c) => ({ ...c, ai: { ...c.ai, mode: m.key } }))} className={cn("flex items-start gap-2 rounded-lg border p-3 text-left hover:border-primary/50", cfg.ai.mode === m.key && "border-primary bg-primary/5 ring-1 ring-primary")}>
                    <m.icon className="mt-0.5 size-4 text-muted-foreground" />
                    <span><span className="block text-sm font-medium">{m.label}</span><span className="block text-[11px] text-muted-foreground">{m.note}</span></span>
                  </button>
                ))}
              </div>
              {cfg.ai.mode === "local" && (
                <div className="grid gap-1.5 sm:max-w-sm">
                  <Label className="text-xs">Hardware</Label>
                  <NativeSelect value={cfg.ai.hardware} onChange={(e) => update((c) => ({ ...c, ai: { ...c.ai, hardware: e.target.value as QuoteConfig["ai"]["hardware"] } }))}>
                    {(["workstation", "server", "cluster"] as const).map((h) => {
                      const p = ctx.book[`ai.local.${h}`]?.price;
                      return <option key={h} value={h}>{h === "workstation" ? "GPU workstation" : h === "server" ? "GPU server" : "Inference cluster"} · {p == null ? "on request" : money(p, 0)}</option>;
                    })}
                  </NativeSelect>
                  <p className="text-[11px] text-muted-foreground">One-time hardware and setup; annual maintenance from year 2.</p>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">7 · Term</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-3 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
              <div className="grid grid-cols-3 gap-2" role="radiogroup" aria-label="Term">
                {(
                  [
                    ["monthly", "Monthly", null],
                    ["annual", "Annual", ctx.book["terms.annual"]?.price],
                    ["3year", "3 years", ctx.book["terms.3year"]?.price],
                  ] as const
                ).map(([key, label, pct]) => (
                  <button key={key} type="button" role="radio" aria-checked={cfg.commercial.term === key} onClick={() => update((c) => ({ ...c, commercial: { ...c.commercial, term: key } }))} className={cn("rounded-lg border p-2.5 text-center text-sm hover:border-primary/50", cfg.commercial.term === key && "border-primary bg-primary/5 ring-1 ring-primary")}>
                    {label}
                    {pct ? <span className="block text-[11px] text-success-ink">save {pct}%</span> : <span className="block text-[11px] text-muted-foreground">no commitment</span>}
                  </button>
                ))}
              </div>
              {currencies.length > 1 && (
                <div className="grid gap-1.5">
                  <Label className="text-xs">Currency</Label>
                  <NativeSelect value={cfg.commercial.currency} onChange={(e) => update((c) => ({ ...c, commercial: { ...c.commercial, currency: e.target.value, fxRate: currencies.find((x) => x.code === e.target.value)?.rate ?? 1 } }))}>
                    {currencies.map((c) => <option key={c.code} value={c.code}>{c.code}</option>)}
                  </NativeSelect>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
        {summary}
      </div>

      <Tabs value={tab} onValueChange={setTab} className="gap-4">
        <TabsList className="flex-wrap" id="design">
          <TabsTrigger value="design">Solution design</TabsTrigger>
          <TabsTrigger value="advisor">Suggested stack</TabsTrigger>
          <TabsTrigger value="upgrades">Upgrade review</TabsTrigger>
          <TabsTrigger value="lines">Line items</TabsTrigger>
        </TabsList>
        <TabsContent value="design">
          <SolutionDesign ctx={ctx} cfg={cfg} money={money} audience="public" facts={facts} onApply={apply} />
        </TabsContent>
        <TabsContent value="advisor">
          <StackAdvisor ctx={ctx} cfg={cfg} money={money} onApply={apply} askAi={aiAdvisor ? publicAdviceAction : undefined} audience="public" />
        </TabsContent>
        <TabsContent value="upgrades">
          <UpgradeReview ctx={ctx} cfg={cfg} money={money} onApply={apply} onSetExisting={(c, key) => update((x) => ({ ...x, existing: { ...x.existing, [c]: key } }))} audience="public" baselineLabel="what you run today" />
        </TabsContent>
        <TabsContent value="lines">
          <Card>
            <CardContent className="overflow-x-auto pt-6">
              {result.lines.length === 0 ? (
                <p className="flex items-center gap-2 text-sm text-muted-foreground"><Layers className="size-4" /> Enter your devices and choose a plan to see the line items.</p>
              ) : (
                <table className="w-full min-w-[32rem] text-sm">
                  <thead>
                    <tr className="border-b text-left text-xs text-muted-foreground">
                      <th className="py-2 pr-3 font-medium">Item</th>
                      <th className="px-2 py-2 font-medium">Detail</th>
                      <th className="px-2 py-2 text-right font-medium">Monthly</th>
                      <th className="px-2 py-2 text-right font-medium">One-time</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {result.lines.map((l) => (
                      <tr key={l.key}>
                        <td className="py-2 pr-3">{l.label}{l.basis === "missing" && <Badge variant="outline" className="ml-1.5 text-[10px]">on request</Badge>}</td>
                        <td className="px-2 py-2 text-xs text-muted-foreground">{l.detail.replace(/price not set/g, "price on request")}</td>
                        <td className="px-2 py-2 text-right tabular">{l.monthly ? money(l.monthly) : "—"}</td>
                        <td className="px-2 py-2 text-right tabular">{l.oneTime ? money(l.oneTime, 0) : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              <p className="mt-3 text-[11px] text-muted-foreground">Before discounts. Tool prices are the vendors&apos; published list prices unless {brand} has set its own; final pricing is confirmed in the formal quote.</p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {leads ? <RequestQuote cfg={cfg} brand={brand} sized={sized} /> : contactEmail && (
        <Card id="request">
          <CardContent className="flex items-center gap-2 py-6 text-sm"><Mail className="size-4" /> For a formal quote, email <a className="font-medium underline" href={`mailto:${contactEmail}`}>{contactEmail}</a>.</CardContent>
        </Card>
      )}
    </div>
  );
}

function RequestQuote({ cfg, brand, sized }: { cfg: QuoteConfig; brand: string; sized: boolean }) {
  const [form, setForm] = React.useState({ name: "", email: "", company: "", phone: "", message: "", consent: false, website: "" });
  const [sent, setSent] = React.useState<string | null>(null);
  const send = useMutation({
    mutationFn: () => requestQuoteAction(cfg, { ...form, consent: form.consent as true }),
    onSuccess: (r) => setSent(r.reference ?? "received"),
    onError: (err) => toast.error(err instanceof Error ? err.message : "Couldn't send your request"),
  });
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));

  if (sent) {
    return (
      <Card id="request" className="scroll-mt-20 border-success/40">
        <CardContent className="flex items-start gap-3 py-6">
          <CircleCheck className="mt-0.5 size-5 text-success-ink" />
          <div>
            <p className="font-semibold">Thanks, we&apos;ve got your request{sent !== "received" ? ` (${sent})` : ""}.</p>
            <p className="text-sm text-muted-foreground">Someone from {brand} will review the estimate with you and send a formal quote.</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card id="request" className="scroll-mt-20">
      <CardHeader>
        <CardTitle className="text-base">Request a formal quote</CardTitle>
        <CardDescription>We&apos;ll receive this estimate as you built it and get back to you. We only use these details to contact you about it.</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="grid gap-3 sm:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault();
            send.mutate();
          }}
        >
          <div className="grid gap-1.5"><Label htmlFor="rq-name" className="text-xs">Your name</Label><Input id="rq-name" required autoComplete="name" value={form.name} onChange={set("name")} /></div>
          <div className="grid gap-1.5"><Label htmlFor="rq-email" className="text-xs">Work email</Label><Input id="rq-email" type="email" required autoComplete="email" value={form.email} onChange={set("email")} /></div>
          <div className="grid gap-1.5"><Label htmlFor="rq-company" className="text-xs">Organization</Label><Input id="rq-company" required autoComplete="organization" value={form.company} onChange={set("company")} /></div>
          <div className="grid gap-1.5"><Label htmlFor="rq-phone" className="text-xs">Phone (optional)</Label><Input id="rq-phone" type="tel" autoComplete="tel" value={form.phone} onChange={set("phone")} /></div>
          <div className="grid gap-1.5 sm:col-span-2"><Label htmlFor="rq-msg" className="text-xs">Anything we should know (optional)</Label><Textarea id="rq-msg" value={form.message} onChange={set("message")} className="min-h-20" maxLength={2000} /></div>
          {/* Hidden from people; spam bots fill it in. */}
          <div aria-hidden className="absolute -left-[9999px] h-0 w-0 overflow-hidden">
            <label>Website<input tabIndex={-1} autoComplete="off" value={form.website} onChange={set("website")} /></label>
          </div>
          <label className="flex items-start gap-2 text-xs sm:col-span-2">
            <input type="checkbox" required checked={form.consent} onChange={(e) => setForm((f) => ({ ...f, consent: e.target.checked }))} className="mt-0.5 size-4 accent-[var(--primary)]" />
            <span>{brand} may contact me about this estimate.</span>
          </label>
          <div className="flex items-center gap-3 sm:col-span-2">
            <Button type="submit" disabled={send.isPending || !sized}>
              {send.isPending ? <Loader2 className="animate-spin" /> : <Send />} Send request
            </Button>
            {!sized && <span className="text-xs text-muted-foreground">Enter your devices first.</span>}
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
