"use client";

import * as React from "react";
import { useMutation } from "@tanstack/react-query";
import { AlertTriangle, Bot, Check, Info, Loader2, Sparkles, Wand2 } from "lucide-react";
import { toast } from "sonner";

import { toolLabel } from "@/lib/integrations/catalog";
import { calculateQuote, toolMonthlyPrice, type PricingContext, type QuoteConfig } from "@/lib/pricing/calculator";
import { ADVISOR_GOALS, adviseStack, type AdviceChange, type AdvisorGoal } from "@/lib/pricing/advisor";
import type { AiAdvice } from "@/lib/pricing/advisor-agent";
import { applyChanges, choiceLabel, controlShort, quoteDelta } from "@/lib/pricing/upgrades";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { Money } from "@/components/pricing/upgrade-review";

const CHANGE: Record<AdviceChange, { label: string; variant: "success" | "info" | "warning" | "soft" | "outline" }> = {
  add: { label: "Add", variant: "success" },
  switch: { label: "Switch", variant: "info" },
  drop: { label: "Drop", variant: "warning" },
  keep: { label: "Keep", variant: "soft" },
  skip: { label: "Not needed", variant: "outline" },
};

const GOALS = Object.keys(ADVISOR_GOALS) as AdvisorGoal[];

interface Props {
  ctx: PricingContext;
  cfg: QuoteConfig;
  money: Money;
  onApply: (config: QuoteConfig) => void;
  // Asks the AI advisor on the server; absent when it's switched off.
  askAi?: (cfg: QuoteConfig, goal: AdvisorGoal) => Promise<AiAdvice>;
  audience: "staff" | "public";
}

function signed(n: number, money: Money) {
  if (Math.abs(n) < 0.005) return "no change";
  return `${n > 0 ? "+" : "−"}${money(Math.abs(n), Math.abs(n) >= 100 ? 0 : 2)}`;
}

export function StackAdvisor({ ctx, cfg, money, onApply, askAi, audience }: Props) {
  const [goal, setGoal] = React.useState<AdvisorGoal>("balanced");
  const rules = React.useMemo(() => adviseStack(cfg, ctx, goal, audience), [cfg, ctx, goal, audience]);
  const [ai, setAi] = React.useState<{ advice: AiAdvice; asked: string } | null>(null);
  const fingerprint = JSON.stringify([cfg, goal]);
  const aiCurrent = ai && ai.asked === fingerprint ? ai.advice : null;

  const ask = useMutation({
    mutationFn: () => askAi!(cfg, goal),
    onSuccess: (advice) => {
      setAi({ advice, asked: fingerprint });
      if (advice.status === "fallback") toast.warning("The AI model didn't answer; showing the rules' suggestion.");
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "The advisor couldn't answer"),
  });

  // Whichever answered, the prices come from the calculator.
  const changes = aiCurrent ? aiCurrent.changes : rules.changes;
  const config = React.useMemo(() => applyChanges(cfg, changes), [cfg, changes]);
  const after = React.useMemo(() => calculateQuote(config, ctx), [config, ctx]);
  const delta = quoteDelta(rules.before, after);
  const fromModel = aiCurrent && aiCurrent.status === "succeeded";
  const your = audience === "public" ? "your" : "the client's";

  const rows = rules.picks.map((p) => {
    const choice = config.tools[p.category] ?? "none";
    const changed = choice !== p.current;
    const change: AdviceChange = !changed ? (p.current === "none" ? "skip" : "keep") : choice === "none" ? "drop" : p.current === "none" ? "add" : "switch";
    const own = ctx.tools.find((t) => t.key === cfg.existing[p.category]);
    const reason = fromModel ? aiCurrent!.reasons[p.category] : p.reasons.join(" · ");
    const tool = ctx.tools.find((t) => t.key === choice);
    const price = tool ? toolMonthlyPrice(tool, config).monthly : 0;
    return { ...p, choice, change, reason, price, ownLabel: own ? toolLabel(own) : undefined, discarded: aiCurrent?.discarded.includes(p.category) };
  });
  const moved = rows.filter((r) => r.change !== "keep" && r.change !== "skip");

  return (
    <div className="flex flex-col gap-4">
      <Card className="surface-glow">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Wand2 className="size-4" /> Suggested stack</CardTitle>
          <CardDescription>
            Based on {your} endpoints by type, users and current tools: one tool per layer, checked to run on {your} devices, with the price difference against what {audience === "public" ? "you have" : "the client has"} now.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div role="radiogroup" aria-label="Goal" className="grid gap-2 sm:grid-cols-3">
            {GOALS.map((g) => (
              <button
                key={g}
                type="button"
                role="radio"
                aria-checked={goal === g}
                onClick={() => setGoal(g)}
                className={cn("flex flex-col gap-1 rounded-lg border p-3 text-left transition-colors hover:border-primary/50", goal === g && "border-primary bg-primary/5 ring-1 ring-primary")}
              >
                <span className="flex items-center justify-between text-sm font-medium">{ADVISOR_GOALS[g].label}{goal === g && <Check className="size-4 text-primary" />}</span>
                <span className="text-[11px] text-muted-foreground">{ADVISOR_GOALS[g].description}</span>
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {askAi ? (
              <Button onClick={() => ask.mutate()} disabled={ask.isPending} variant={aiCurrent ? "outline" : "default"}>
                {ask.isPending ? <Loader2 className="animate-spin" /> : <Sparkles />}
                {aiCurrent ? "Ask again" : "Ask the AI advisor"}
              </Button>
            ) : (
              <span className="text-xs text-muted-foreground">Suggestions from the advisor&apos;s rules.</span>
            )}
            {ai && !aiCurrent && <span className="text-xs text-warning-ink">The estimate changed since the AI answered; these are the rules&apos; suggestions.</span>}
          </div>

          {aiCurrent && (
            <div className="rounded-lg border bg-muted/40 p-3 text-sm">
              <p className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                <Bot className="size-3.5 text-chart-4" />
                {aiCurrent.status === "succeeded" ? `${aiCurrent.engine}${aiCurrent.model ? ` · ${aiCurrent.model}` : ""}${aiCurrent.isLocal ? " (local)" : ""}` : aiCurrent.status === "rules" ? "Rules engine (no AI model is configured)" : "Rules engine (the AI model didn't answer)"}
              </p>
              <p className="mt-1.5 text-pretty">{aiCurrent.summary}</p>
              {aiCurrent.discarded.length > 0 && (
                <p className="mt-1.5 flex items-start gap-1.5 text-[11px] text-muted-foreground"><Info className="mt-0.5 size-3 shrink-0" /> The AI named a tool that isn&apos;t in the catalog for {aiCurrent.discarded.join(", ")}; the rules&apos; pick is shown there instead.</p>
              )}
              {fromModel && <p className="mt-1.5 text-[11px] text-muted-foreground">AI suggestions can be wrong. Prices below are calculated from the catalog, not by the AI.</p>}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardContent className="flex flex-col divide-y p-0">
          {rows.map((r) => (
            <div key={r.category} className={cn("grid gap-2 p-4 sm:grid-cols-[11rem_minmax(0,1fr)_7.5rem]", (r.change === "skip" || r.change === "keep") && "bg-muted/20")}>
              <div>
                <p className="text-sm font-medium">{r.label}</p>
                <Badge variant={CHANGE[r.change].variant} className="mt-1 text-[10px]">{CHANGE[r.change].label}</Badge>
              </div>
              <div className="min-w-0">
                <p className="text-sm">
                  {r.change === "switch" ? (
                    <>
                      <span className="text-muted-foreground line-through decoration-muted-foreground/60">{choiceLabel(ctx, r.current, r.ownLabel, audience)}</span> → <span className="font-medium">{choiceLabel(ctx, r.choice, undefined, audience)}</span>
                    </>
                  ) : r.change === "drop" ? (
                    <span className="text-muted-foreground line-through decoration-muted-foreground/60">{choiceLabel(ctx, r.current, r.ownLabel, audience)}</span>
                  ) : r.change === "skip" ? (
                    <span className="text-muted-foreground">—</span>
                  ) : (
                    <span className="font-medium">{choiceLabel(ctx, r.choice, r.ownLabel, audience)}</span>
                  )}
                </p>
                {r.reason && <p className="mt-0.5 text-xs text-muted-foreground">{r.reason}</p>}
                {r.discarded && <p className="mt-0.5 text-[11px] text-warning-ink">AI pick discarded (not in the catalog)</p>}
              </div>
              <div className="text-right text-sm tabular">
                {r.change === "drop" ? (
                  <span className="text-xs text-muted-foreground">removed</span>
                ) : r.change === "add" || r.change === "switch" ? (
                  r.price == null ? <span className="text-xs text-warning-ink">price on request</span> : <>{money(r.price, 0)}<span className="text-xs text-muted-foreground">/mo</span></>
                ) : (
                  <span className="text-xs text-muted-foreground">{r.change === "keep" ? "unchanged" : ""}</span>
                )}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardContent className="flex flex-col gap-3 py-4">
          <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
            <div><dt className="text-[11px] text-muted-foreground">Now</dt><dd className="font-medium tabular">{money(rules.before.monthlyNet, 0)}/mo</dd></div>
            <div><dt className="text-[11px] text-muted-foreground">Suggested</dt><dd className="font-semibold tabular">{money(after.monthlyNet, 0)}/mo</dd></div>
            <div><dt className="text-[11px] text-muted-foreground">Difference</dt><dd className={cn("font-medium tabular", delta.monthly < 0 && "text-success-ink")}>{signed(delta.monthly, money)}/mo</dd></div>
            <div><dt className="text-[11px] text-muted-foreground">3-year difference</dt><dd className="font-medium tabular">{signed(delta.threeYear, money)}</dd></div>
          </dl>
          {delta.gapsClosed.length > 0 && <p className="text-xs text-success-ink">Closes essential gaps: {delta.gapsClosed.map(controlShort).join(", ")}.</p>}
          {after.gaps.length > 0 && <p className="text-xs text-destructive">Still missing: {after.gaps.map(controlShort).join(", ")}.</p>}
          {rules.notes.length > 0 && (
            <ul className="flex flex-col gap-1 text-xs text-muted-foreground">
              {rules.notes.map((n) => (
                <li key={n} className="flex items-start gap-1.5"><AlertTriangle className="mt-0.5 size-3 shrink-0" /> {n}</li>
              ))}
            </ul>
          )}
          <div className="flex justify-end">
            <Button onClick={() => onApply(config)} disabled={moved.length === 0}>
              <Check /> Use this stack{moved.length ? ` (${moved.length} change${moved.length === 1 ? "" : "s"})` : ""}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
