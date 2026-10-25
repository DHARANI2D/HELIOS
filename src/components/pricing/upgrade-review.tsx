"use client";

import * as React from "react";
import { ArrowDownRight, ArrowUpRight, CircleCheck, CircleDashed, Info, Layers, Minus, Plus, TrendingUp, Undo2 } from "lucide-react";

import { toolLabel } from "@/lib/integrations/catalog";
import type { PricingContext, QuoteConfig } from "@/lib/pricing/calculator";
import { controlShort, priceChanges, reviewUpgrades, type CategoryReview, type OptionKind, type UpgradeOption } from "@/lib/pricing/upgrades";
import type { PlatformFit } from "@/lib/pricing/endpoint-mix";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";

const KIND: Record<OptionKind, { label: string; variant: "success" | "info" | "warning" | "soft" | "outline" }> = {
  upgrade: { label: "Upgrade", variant: "success" },
  cheaper: { label: "Same cover, cheaper", variant: "info" },
  "trade-off": { label: "Trade-off", variant: "warning" },
  equivalent: { label: "Equivalent", variant: "soft" },
  downgrade: { label: "Less cover", variant: "outline" },
};

export type Money = (usd: number, decimals?: number) => string;

function Delta({ value, money, suffix = "/mo" }: { value: number | null; money: Money; suffix?: string }) {
  if (value == null) return <span className="text-xs text-warning-ink">price on request</span>;
  if (Math.abs(value) < 0.005) return <span className="text-xs text-muted-foreground">same price</span>;
  const up = value > 0;
  return (
    <span className={cn("inline-flex items-center gap-0.5 text-sm font-medium tabular", up ? "text-foreground" : "text-success-ink")}>
      {up ? <ArrowUpRight className="size-3.5" /> : <ArrowDownRight className="size-3.5" />}
      {up ? "+" : "−"}
      {money(Math.abs(value), Math.abs(value) >= 100 ? 0 : 2)}
      <span className="text-xs font-normal text-muted-foreground">{suffix}</span>
    </span>
  );
}

function FitText({ fit }: { fit: PlatformFit | null }) {
  if (!fit || fit.relevant === 0) return null;
  if (fit.agentless) return <span className="text-[11px] text-muted-foreground">no endpoint agent</span>;
  if (!fit.unsupported.length) return <span className="text-[11px] text-success-ink">runs on all {fit.relevant}{fit.unknown ? ` known (${fit.unknown} unknown OS)` : ""}</span>;
  return <span className="text-[11px] text-destructive">misses {fit.unsupported.map((u) => `${u.count} ${u.label}`).join(", ")}</span>;
}

function OptionRow({ option, selected, onToggle, money, hasBaseline }: { option: UpgradeOption; selected: boolean; onToggle: () => void; money: Money; hasBaseline: boolean }) {
  const k = KIND[option.kind];
  // Controls this tool lacks that another layer still provides aren't lost.
  const coveredElsewhere = option.loses.filter((c) => !option.lostFromStack.includes(c));
  return (
    <label className={cn("grid cursor-pointer gap-2 rounded-lg border p-3 transition-colors hover:border-primary/50 sm:grid-cols-[auto_minmax(0,1fr)_auto] sm:items-center", selected && "border-primary bg-primary/5 ring-1 ring-primary")}>
      <input type="checkbox" checked={selected} onChange={onToggle} className="size-4 accent-[var(--primary)]" aria-label={`Use ${toolLabel(option.tool)}`} />
      <div className="min-w-0">
        <p className="flex flex-wrap items-center gap-1.5 text-sm font-medium">
          {toolLabel(option.tool)}
          <Badge variant={k.variant} className="text-[10px]">{k.label}</Badge>
        </p>
        <p className="mt-1 flex flex-wrap items-center gap-1">
          {option.gains.map((c) => (
            <Badge key={`g${c}`} variant="outline" className={cn("font-mono text-[10px]", option.newToStack.includes(c) ? "border-success/50 text-success-ink" : "text-muted-foreground")} title={option.newToStack.includes(c) ? "New to the stack" : "Another layer already has it"}>
              <Plus /> {controlShort(c)}
            </Badge>
          ))}
          {option.lostFromStack.map((c) => (
            <Badge key={`l${c}`} variant="outline" className="border-destructive/50 font-mono text-[10px] text-destructive" title="No other layer provides it">
              <Minus /> {controlShort(c)}
            </Badge>
          ))}
          {option.alertsGain > 0 && <Badge variant="soft" className="text-[10px]">+ alerts to SOC</Badge>}
          {option.alertsGain < 0 && <Badge variant="outline" className="text-[10px] text-destructive">no alerts to SOC</Badge>}
          {option.actionsGain > 0 && <Badge variant="soft" className="text-[10px]">+{option.actionsGain} response actions</Badge>}
          <FitText fit={option.fit} />
        </p>
        {coveredElsewhere.length > 0 && <p className="mt-1 text-[11px] text-muted-foreground">Lacks {coveredElsewhere.map(controlShort).join(", ")}; another layer still provides {coveredElsewhere.length === 1 ? "it" : "them"}.</p>}
      </div>
      <div className="text-right">
        {option.monthly == null ? (
          <span className="text-xs text-warning-ink">price on request</span>
        ) : option.priceDelta == null ? (
          <span className="text-xs text-muted-foreground">current price unknown</span>
        ) : !hasBaseline && option.monthly === 0 ? (
          <span className="text-xs text-muted-foreground">no licence fee</span>
        ) : (
          <Delta value={option.priceDelta} money={money} />
        )}
        <p className="text-[11px] text-muted-foreground tabular">{option.monthly == null ? "" : `${money(option.monthly, 0)}/mo for this size`}</p>
      </div>
    </label>
  );
}

function baselineText(r: CategoryReview, money: Money, audience: Props["audience"]) {
  const own = audience === "public" ? "Your own" : "Client's own";
  if (r.source === "none") return "Not in the stack";
  if (r.source === "unknown-own") return `${own} tool, not named`;
  const price = r.baselineMonthly == null ? "price unknown" : `${money(r.baselineMonthly, 0)}/mo${r.source === "existing" ? " at catalog price" : ""}`;
  return `${r.source === "existing" ? `${own} ` : ""}${toolLabel(r.baseline!)} · ${price}`;
}

interface Props {
  ctx: PricingContext;
  cfg: QuoteConfig;
  money: Money;
  onApply: (config: QuoteConfig) => void;
  // Names the client's own tool in a layer (the "existing" record).
  onSetExisting?: (category: string, toolKey: string) => void;
  // Wording: "your" for a visitor, "the client's" for staff.
  audience: "staff" | "public";
  baselineLabel?: string;
}

export function UpgradeReview({ ctx, cfg, money, onApply, onSetExisting, audience, baselineLabel }: Props) {
  const reviews = React.useMemo(() => reviewUpgrades(cfg, ctx), [cfg, ctx]);
  const [selected, setSelected] = React.useState<Record<string, string>>({});
  const [showAll, setShowAll] = React.useState(false);
  const priced = React.useMemo(() => priceChanges(cfg, ctx, selected), [cfg, ctx, selected]);
  const count = Object.keys(selected).length;
  const your = audience === "public" ? "your" : "the client's";

  // A layer is worth showing when something there is better, or it's empty
  // and a tool would add protection.
  const withBaseline = reviews.filter((r) => r.source === "existing" || r.source === "estimate" || r.source === "unknown-own");
  const missing = reviews.filter((r) => r.source === "none" && r.options.some((o) => o.newToStack.length));
  const visible = (r: CategoryReview) => r.options.filter((o) => showAll || o.kind === "upgrade" || o.kind === "cheaper" || selected[r.category.key] === o.tool.key);

  const toggle = (category: string, key: string) =>
    setSelected((s) => {
      const next = { ...s };
      if (next[category] === key) delete next[category];
      else next[category] = key;
      return next;
    });

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><TrendingUp className="size-4" /> Upgrade review</CardTitle>
          <CardDescription>
            Compared with {baselineLabel ?? `${your} current stack`}: what each alternative adds (+) or takes away (−), whether it runs on {your} devices, and the price difference for this size. Tick the
            changes to see what they do to the whole estimate.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            <Switch checked={showAll} onCheckedChange={setShowAll} /> Also show trade-offs and tools with less cover
          </label>
          {!cfg.profile.mix && (
            <p className="flex items-start gap-1.5 text-xs text-muted-foreground"><Info className="mt-0.5 size-3.5 shrink-0" /> Enter endpoints by operating system to check that each tool runs on every device.</p>
          )}
        </CardContent>
      </Card>

      {withBaseline.length === 0 && (
        <Card>
          <CardContent className="flex items-start gap-2 py-6 text-sm text-muted-foreground">
            <Layers className="mt-0.5 size-4 shrink-0" />
            {audience === "public" ? "Tell us which tools you run today (or pick tools for the estimate) and we'll compare the alternatives." : "This stack has no tools yet. Pick tools in Build, or open a client or a saved quote to review its upgrades."}
          </CardContent>
        </Card>
      )}

      {withBaseline.map((r) => {
        const options = visible(r);
        return (
          <Card key={r.category.key}>
            <CardHeader className="pb-3">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <CardTitle className="text-sm">{r.category.label}</CardTitle>
                <span className="text-xs text-muted-foreground">
                  Today: <span className="font-medium text-foreground">{baselineText(r, money, audience)}</span> {r.baselineFit && <FitText fit={r.baselineFit} />}
                </span>
              </div>
            </CardHeader>
            <CardContent className="flex flex-col gap-2">
              {r.source === "unknown-own" && onSetExisting && (
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="text-muted-foreground">Which tool is it?</span>
                  <NativeSelect className="h-8 w-auto text-xs" value="" onChange={(e) => e.target.value && onSetExisting(r.category.key, e.target.value)} aria-label={`${r.category.label}: current tool`}>
                    <option value="">Choose…</option>
                    {ctx.tools.filter((t) => t.category === r.category.key).map((t) => (
                      <option key={t.key} value={t.key}>{toolLabel(t)}</option>
                    ))}
                  </NativeSelect>
                </div>
              )}
              {options.length === 0 ? (
                <p className="flex items-center gap-1.5 text-xs text-muted-foreground"><CircleCheck className="size-3.5 text-success-ink" /> Nothing in the catalog beats it for this client{showAll ? "" : " (switch on trade-offs to see every alternative)"}.</p>
              ) : (
                options.map((o) => <OptionRow key={o.tool.key} option={o} selected={selected[r.category.key] === o.tool.key} onToggle={() => toggle(r.category.key, o.tool.key)} money={money} hasBaseline={!!r.baseline} />)
              )}
            </CardContent>
          </Card>
        );
      })}

      {missing.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">Layers {audience === "public" ? "you don't have yet" : "not in the stack"}</CardTitle>
            <CardDescription>The best-rated tool for each, by the protection it adds.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {missing.map((r) => {
              const best = r.options.find((o) => o.newToStack.length)!;
              const option = r.options.find((o) => o.tool.key === selected[r.category.key]) ?? best;
              return (
                <div key={r.category.key} className="grid gap-1">
                  <p className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground"><CircleDashed className="size-3.5" /> {r.category.label}</p>
                  <OptionRow option={option} selected={selected[r.category.key] === option.tool.key} onToggle={() => toggle(r.category.key, option.tool.key)} money={money} hasBaseline={false} />
                </div>
              );
            })}
          </CardContent>
        </Card>
      )}

      <div className="sticky bottom-3 z-10">
        <div className={cn("flex flex-col gap-3 rounded-xl border bg-card/95 p-4 shadow-lg backdrop-blur sm:flex-row sm:items-center sm:justify-between", count === 0 && "opacity-90")}>
          {count === 0 ? (
            <p className="text-sm text-muted-foreground">Tick upgrades above to see the new price.</p>
          ) : (
            <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm sm:grid-cols-4">
              <div><dt className="text-[11px] text-muted-foreground">Monthly</dt><dd><Delta value={priced.delta.monthly} money={money} /></dd></div>
              <div><dt className="text-[11px] text-muted-foreground">One-time</dt><dd><Delta value={priced.delta.oneTime} money={money} suffix="" /></dd></div>
              <div><dt className="text-[11px] text-muted-foreground">Year 1</dt><dd><Delta value={priced.delta.year1} money={money} suffix="" /></dd></div>
              <div><dt className="text-[11px] text-muted-foreground">New monthly</dt><dd className="text-sm font-semibold tabular">{money(priced.after.monthlyNet, 0)}</dd></div>
              {(priced.delta.gapsClosed.length > 0 || priced.delta.gapsOpened.length > 0 || priced.delta.missing.length > 0) && (
                <div className="col-span-full text-[11px]">
                  {priced.delta.gapsClosed.length > 0 && <span className="text-success-ink">Closes essential gaps: {priced.delta.gapsClosed.map(controlShort).join(", ")}. </span>}
                  {priced.delta.gapsOpened.length > 0 && <span className="font-medium text-destructive">Opens essential gaps: {priced.delta.gapsOpened.map(controlShort).join(", ")}. </span>}
                  {priced.delta.missing.length > 0 && <span className="text-warning-ink">Priced on request: {priced.delta.missing.join("; ")}.</span>}
                </div>
              )}
            </dl>
          )}
          <div className="flex shrink-0 gap-2">
            {count > 0 && (
              <Button variant="ghost" size="sm" onClick={() => setSelected({})}><Undo2 /> Clear</Button>
            )}
            <Button
              size="sm"
              disabled={count === 0}
              onClick={() => {
                onApply(priced.config);
                setSelected({});
              }}
            >
              Apply {count || ""} change{count === 1 ? "" : "s"}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
