"use client";

import * as React from "react";
import { ArrowDown, Check, CircleCheck, Info, Plus, Printer, Radar, ShieldAlert, Siren, Workflow, X } from "lucide-react";

import { capabilityName } from "@/lib/assets/capabilities";
import { designSolution, type DeployItem, type PlatformFacts } from "@/lib/assets/designer";
import { ADVISOR_GOALS, type AdvisorGoal } from "@/lib/pricing/advisor";
import type { PricingContext, QuoteConfig } from "@/lib/pricing/calculator";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { PriorityBadge } from "@/components/pricing/surface-coverage";
import type { Money } from "@/components/pricing/upgrade-review";

const GOALS = Object.keys(ADVISOR_GOALS) as AdvisorGoal[];

function DeployRow({ item }: { item: DeployItem }) {
  const icon =
    item.status === "in-place" ? <CircleCheck className="size-3.5 shrink-0 text-success-ink" /> : item.status === "suggested" ? <Plus className="size-3.5 shrink-0 text-info-ink" /> : <X className="size-3.5 shrink-0 text-destructive" />;
  return (
    <li className="flex items-start gap-1.5 text-xs">
      <span className="mt-0.5">{icon}</span>
      <span className="min-w-0">
        <span className={cn(item.required && "font-medium")}>{capabilityName(item.capability)}</span>
        {!item.required && <span className="text-muted-foreground"> · recommended</span>}
        <span className="block text-[11px] text-muted-foreground">
          {item.status === "in-place" ? `In place: ${item.by.join(", ")}` : item.status === "suggested" ? `Suggested: ${item.by.join(", ")}` : "Not covered by any tool yet"}
        </span>
      </span>
    </li>
  );
}

function Column({ icon: Icon, title, items }: { icon: typeof Radar; title: string; items: string[] }) {
  return (
    <div>
      <p className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground"><Icon className="size-3.5" /> {title}</p>
      <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs">
        {items.map((t) => <li key={t}>{t}</li>)}
      </ul>
    </div>
  );
}

interface Props {
  ctx: PricingContext;
  cfg: QuoteConfig;
  money: Money;
  audience: "staff" | "public";
  facts: PlatformFacts | null;
  onApply: (config: QuoteConfig) => void;
}

// The company-wide security design for the current answers and estate.
export function SolutionDesign({ ctx, cfg, money, audience, facts, onApply }: Props) {
  const [goal, setGoal] = React.useState<AdvisorGoal>("balanced");
  const design = React.useMemo(() => designSolution(cfg, ctx, goal, audience, facts), [cfg, ctx, goal, audience, facts]);
  const changes = Object.keys(design.advice.changes).length;
  const unanswered = design.profile.filter((p) => p.value === "—").length;

  return (
    <div className="flex flex-col gap-4 print:gap-2">
      <Card className="surface-glow">
        <CardHeader>
          <CardDescription>Solution design</CardDescription>
          <CardTitle className="text-xl">{design.title}</CardTitle>
          <dl className="mt-2 flex flex-wrap gap-1.5">
            {design.profile.map((p) => (
              <div key={p.label} className="rounded-md border bg-background/60 px-2 py-1 text-xs">
                <dt className="inline text-muted-foreground">{p.label}: </dt>
                <dd className="inline font-medium">{p.value}</dd>
              </div>
            ))}
          </dl>
          {unanswered > 0 && <p className="mt-1 flex items-center gap-1.5 text-[11px] text-muted-foreground"><Info className="size-3" /> Answer the organization questions above to sharpen the priorities.</p>}
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="grid gap-3 sm:grid-cols-2">
            {[
              { label: audience === "public" ? "Your coverage today" : "Coverage today", value: design.coverageBefore },
              { label: "With the suggested stack", value: design.coverageAfter },
            ].map((s) => (
              <div key={s.label}>
                <div className="flex items-baseline justify-between text-xs"><span className="text-muted-foreground">{s.label}</span><span className="text-lg font-semibold tabular">{s.value}%</span></div>
                <div className="mt-1 h-2 overflow-hidden rounded-full bg-muted"><div className={cn("h-full rounded-full", s.value >= 90 ? "bg-success" : s.value >= 60 ? "bg-warning" : "bg-destructive")} style={{ width: `${s.value}%` }} /></div>
              </div>
            ))}
          </div>
          <div role="radiogroup" aria-label="Goal" className="no-print flex flex-wrap gap-1.5">
            {GOALS.map((g) => (
              <button key={g} type="button" role="radio" aria-checked={goal === g} onClick={() => setGoal(g)} title={ADVISOR_GOALS[g].description} className={cn("rounded-full border px-3 py-1 text-xs hover:bg-accent", goal === g && "border-primary bg-primary text-primary-foreground hover:bg-primary/90")}>
                {ADVISOR_GOALS[g].label}
              </button>
            ))}
          </div>
          <div className="no-print flex flex-wrap items-center gap-2">
            <Button onClick={() => onApply(design.advice.config)} disabled={changes === 0}>
              <Check /> Use this design&apos;s stack{changes ? ` (${changes} change${changes === 1 ? "" : "s"}, ${design.advice.delta.monthly >= 0 ? "+" : "−"}${money(Math.abs(design.advice.delta.monthly), 0)}/mo)` : ""}
            </Button>
            <Button variant="outline" onClick={() => window.print()}><Printer /> Print</Button>
          </div>
          {design.guidance.length > 0 && (
            <ul className="flex flex-col gap-1 rounded-lg border bg-muted/30 p-3 text-xs">
              {design.guidance.map((g) => <li key={g} className="flex items-start gap-1.5"><Info className="mt-0.5 size-3 shrink-0 text-info-ink" /> {g}</li>)}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Priorities</CardTitle>
          <CardDescription>The order to protect things in, for this organization. P1 first.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          {design.groups.length === 0 ? (
            <p className="text-sm text-muted-foreground">Enter devices, users and the rest of the estate to build the design.</p>
          ) : (
            <table className="w-full min-w-[34rem] text-sm">
              <thead>
                <tr className="border-b text-left text-xs text-muted-foreground">
                  <th className="py-2 pr-3 font-medium">Priority</th>
                  <th className="px-2 py-2 font-medium">Asset group</th>
                  <th className="px-2 py-2 font-medium">Main risk</th>
                  <th className="px-2 py-2 font-medium">What&apos;s counted</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {design.groups.map((g) => (
                  <tr key={g.info.key}>
                    <td className="py-2 pr-3 align-top"><PriorityBadge priority={g.priority} /></td>
                    <td className="px-2 py-2 align-top">
                      <span className="font-medium">{g.info.label}</span>
                      {g.reasons.map((r) => <span key={r} className="block text-[11px] text-muted-foreground">{r}</span>)}
                      {!g.inScope && <Badge variant="outline" className="mt-0.5 text-[10px]">later phase</Badge>}
                    </td>
                    <td className="px-2 py-2 align-top text-xs text-muted-foreground">{g.info.risk}</td>
                    <td className="px-2 py-2 align-top text-xs">{g.describe}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      {design.groups.map((g) => (
        <Card key={g.info.key} className={cn(!g.inScope && "opacity-80")}>
          <CardHeader className="pb-2">
            <CardTitle className="flex flex-wrap items-center gap-2 text-base">
              <PriorityBadge priority={g.priority} /> {g.info.label}
              <span className="text-xs font-normal text-muted-foreground">{g.describe}</span>
            </CardTitle>
            <CardDescription>{g.info.description}</CardDescription>
            <ul className="mt-1 flex flex-wrap gap-1">
              {g.info.examples.map((e) => <li key={e} className="rounded-md bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">{e}</li>)}
            </ul>
          </CardHeader>
          <CardContent className="grid gap-4 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,2fr)]">
            <div>
              <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">What to deploy</p>
              <ul className="mt-1 flex flex-col gap-1.5">{g.deploy.map((d) => <DeployRow key={d.capability} item={d} />)}</ul>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <Column icon={Radar} title="Telemetry to collect" items={g.info.telemetry} />
              <Column icon={ShieldAlert} title="What we detect" items={g.info.detections} />
              <Column icon={Siren} title="How we respond" items={g.info.response} />
            </div>
          </CardContent>
        </Card>
      ))}

      {design.groups.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-base"><Workflow className="size-4" /> Centralized detection and response</CardTitle>
            <CardDescription>Every asset group feeds one platform; nothing is managed on its own.</CardDescription>
          </CardHeader>
          <CardContent>
            <ol className="flex flex-col items-stretch">
              {design.architecture.map((layer, i) => (
                <li key={layer.layer} className="flex flex-col items-center">
                  <div className={cn("w-full rounded-lg border p-3", i === 2 ? "border-primary/50 bg-primary/5" : "bg-card")}>
                    <p className="text-sm font-semibold">{layer.layer}</p>
                    <ul className="mt-1 space-y-0.5 text-xs text-muted-foreground">
                      {layer.items.map((it) => <li key={it}>{it}</li>)}
                    </ul>
                  </div>
                  {i < design.architecture.length - 1 && <ArrowDown className="my-1 size-4 text-muted-foreground" aria-hidden />}
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      )}

      {design.phases.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Rollout</CardTitle>
            <CardDescription>In priority order. The tools are the stack advisor&apos;s picks for the &quot;{ADVISOR_GOALS[goal].label}&quot; goal.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-3">
            {design.phases.map((p) => (
              <div key={p.phase} className="rounded-lg border p-3">
                <p className="text-sm font-semibold">{p.title}</p>
                <ul className="mt-1 list-disc space-y-1 pl-4 text-xs">{p.items.map((it) => <li key={it}>{it}</li>)}</ul>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {design.notCounted.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Not counted yet</CardTitle>
            <CardDescription>Add counts for these to bring them into the design, or confirm {audience === "public" ? "you don't have" : "the client doesn't have"} them.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-1.5">
            {design.notCounted.map((c) => <Badge key={c.key} variant="outline" title={c.examples.join(" · ")}>{c.label}</Badge>)}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
