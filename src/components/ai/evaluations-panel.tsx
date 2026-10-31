"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, FlaskConical, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { runEvaluationAction } from "@/app/(app)/ai/actions";
import { formatRelative } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { NativeSelect } from "@/components/ui/native-select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { unwrap } from "@/lib/action-result";

type Target = { kind: "builtin" } | { kind: "env" } | { kind: "provider"; id: string };
type EvalAgent = "triage" | "phishing" | "threat_intel" | "investigator";

export interface EvalTargetView {
  value: string; // "builtin" | "env" | provider id
  target: Target;
  label: string;
  model: string;
}

export interface CaseResultView {
  id: string;
  kind: string;
  label: string;
  verdict: string;
  verdictScore: number;
  expected: number;
  matched: number;
  falseContainment: string[];
  injectionResisted: boolean | null;
  engine: string;
  error?: string;
  // Investigation scenarios: the facts it found and missed.
  discovered?: string[];
  missed?: string[];
  lookups?: number;
}

export interface ScorecardView {
  model: string;
  agentKey: EvalAgent;
  score: number;
  passed: boolean;
  cases: number;
  evaluatedAt: string;
  verdictAccuracy: number | null;
  actionRecall: number | null;
  falseContainments: number | null;
  injectionFailures: number | null;
  discovery: number | null;
  reasons: string[];
  results: CaseResultView[];
  inUse: string[];
}

interface Props {
  targets: EvalTargetView[];
  scorecards: ScorecardView[];
  running: Array<{ key: string; label: string; startedAt: string }>;
  golden: { total: number; byKind: Record<string, number>; why: Record<string, string>; investigation: { total: number; discovery: number; grounding: number } };
  pass: { verdictAccuracy: number; actionRecall: number };
  // Model choices by clients or users with no passing scorecard.
  unevaluated: string[];
  now: string;
  canConfigure: boolean;
}

const AGENT_LABEL: Record<EvalAgent, string> = { triage: "Triage", phishing: "Phishing analyst", threat_intel: "Threat-intel enricher", investigator: "Investigation agent" };
const KIND_LABEL: Record<string, string> = { attack: "attacks", benign: "benign", lookalike: "look-alikes", adversarial: "with planted instructions" };
const pct = (n: number | null) => (n == null ? "—" : `${Math.round(n * 100)}%`);

export function EvaluationsPanel({ targets, scorecards, running, golden, pass, unevaluated, now: nowIso, canConfigure }: Props) {
  const router = useRouter();
  const now = new Date(nowIso);
  const [target, setTarget] = React.useState(targets[0]?.value ?? "builtin");
  const [agent, setAgent] = React.useState<EvalAgent>("triage");
  const [open, setOpen] = React.useState<string | null>(null);

  // Model runs finish after the response; refresh until they're done.
  React.useEffect(() => {
    if (!running.length) return;
    const t = setInterval(() => router.refresh(), 5000);
    return () => clearInterval(t);
  }, [running.length, router]);

  const run = useMutation({
    mutationFn: () => unwrap(runEvaluationAction({ target: targets.find((t) => t.value === target)!.target, agentKey: agent })),
    onSuccess: (r) => {
      if (r.finished) toast[r.passed ? "success" : "warning"](`${r.model}: ${Math.round((r.score ?? 0) * 100)}% — ${r.passed ? "passed" : "below the bar"}`);
      else toast.success(`Evaluating ${r.model}: one model call per case, the scorecard appears here when it's done`);
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        {golden.total} labelled cases ({Object.entries(golden.byKind).map(([k, n]) => `${n} ${KIND_LABEL[k] ?? k}`).join(", ")}), run through the same pipeline as first response. To pass, a model needs
        verdicts right in at least {pass.verdictAccuracy * 100}% of cases, at least {pass.actionRecall * 100}% of the containment an analyst would take, no containment an analyst
        wouldn&apos;t take, and it must never be fooled by planted instructions. A model a client or user picks only suggests until it passes for that agent.
      </p>
      <p className="text-sm text-muted-foreground">
        The investigation agent is scored on {golden.investigation.total} scenarios of its own. Each seeds a short-lived test client with the telemetry and inventory its
        tools will search, then removes it. On top of the bars above, it must find at least {golden.investigation.discovery * 100}% of what the alerts didn&apos;t show (the
        second host, the sign-in that followed, the jump server behind the &quot;lateral movement&quot;), and at least {golden.investigation.grounding * 100}% of its findings
        must cite real evidence.
      </p>

      {unevaluated.length > 0 && (
        <p className="rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm">
          Only suggesting until evaluated: {unevaluated.join("; ")}.
        </p>
      )}

      {canConfigure && (
        <div className="flex flex-wrap items-end gap-2">
          <label className="flex flex-col gap-1 text-xs text-muted-foreground">
            Model
            <NativeSelect value={target} onChange={(e) => setTarget(e.target.value)} aria-label="Model to evaluate" className="min-w-56">
              {targets.map((t) => (
                <option key={t.value} value={t.value}>{t.label} · {t.model}</option>
              ))}
            </NativeSelect>
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted-foreground">
            Agent
            <NativeSelect value={agent} onChange={(e) => setAgent(e.target.value as EvalAgent)} aria-label="Agent to evaluate">
              {(Object.keys(AGENT_LABEL) as EvalAgent[]).map((k) => (
                <option key={k} value={k}>{AGENT_LABEL[k]}</option>
              ))}
            </NativeSelect>
          </label>
          <Button onClick={() => run.mutate()} disabled={run.isPending || !targets.length}>
            {run.isPending ? <Loader2 className="size-4 animate-spin" /> : <FlaskConical className="size-4" />} Run evaluation
          </Button>
        </div>
      )}

      {running.length > 0 && (
        <ul className="flex flex-col gap-1 text-sm">
          {running.map((r) => (
            <li key={r.key} className="flex items-center gap-2 text-muted-foreground">
              <Loader2 className="size-3.5 animate-spin" /> Evaluating {r.label} · started {formatRelative(r.startedAt, now)}
            </li>
          ))}
        </ul>
      )}

      {scorecards.length === 0 ? (
        <p className="text-sm text-muted-foreground">No model has been evaluated yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-6" />
                <TableHead>Model</TableHead>
                <TableHead>Agent</TableHead>
                <TableHead className="text-right">Score</TableHead>
                <TableHead className="text-right">Verdicts</TableHead>
                <TableHead className="text-right">Containment recall</TableHead>
                <TableHead className="text-right">Wrong containment</TableHead>
                <TableHead className="text-right">Fooled</TableHead>
                <TableHead className="text-right">Found</TableHead>
                <TableHead>Result</TableHead>
                <TableHead className="text-right">Evaluated</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scorecards.map((c) => {
                const key = `${c.model}:${c.agentKey}`;
                const expanded = open === key;
                return (
                  <React.Fragment key={key}>
                    <TableRow>
                      <TableCell>
                        <button type="button" onClick={() => setOpen(expanded ? null : key)} aria-label={expanded ? "Hide case results" : "Show case results"} aria-expanded={expanded} className="text-muted-foreground hover:text-foreground">
                          {expanded ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
                        </button>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {c.model}
                        {c.inUse.length > 0 && <p className="font-sans text-[11px] text-muted-foreground">Picked by {c.inUse.join(", ")}</p>}
                      </TableCell>
                      <TableCell className="text-xs">{AGENT_LABEL[c.agentKey] ?? c.agentKey}</TableCell>
                      <TableCell className="text-right tabular-nums">{pct(c.score)}</TableCell>
                      <TableCell className="text-right tabular-nums">{pct(c.verdictAccuracy)}</TableCell>
                      <TableCell className="text-right tabular-nums">{pct(c.actionRecall)}</TableCell>
                      <TableCell className="text-right tabular-nums">{c.falseContainments ?? "—"}</TableCell>
                      <TableCell className="text-right tabular-nums">{c.injectionFailures ?? "—"}</TableCell>
                      <TableCell className="text-right tabular-nums">{pct(c.discovery)}</TableCell>
                      <TableCell className="max-w-72">
                        <Badge variant={c.passed ? "success" : "destructive"}>{c.passed ? "Passed" : "Below the bar"}</Badge>
                        {c.reasons.map((r) => (
                          <p key={r} className="mt-0.5 text-[11px] text-muted-foreground">{r}</p>
                        ))}
                      </TableCell>
                      <TableCell className="text-right text-xs text-muted-foreground">{formatRelative(c.evaluatedAt, now)}</TableCell>
                    </TableRow>
                    {expanded && (
                      <TableRow>
                        <TableCell colSpan={11} className="bg-muted/30">
                          <ul className="flex flex-col gap-1.5 py-1 text-xs">
                            {c.results.map((r) => {
                              const wrong = r.falseContainment.length > 0 || r.injectionResisted === false || r.verdictScore === 0 || !!r.error;
                              return (
                                <li key={r.id} className="flex flex-wrap items-baseline gap-x-2">
                                  <Badge variant={wrong ? "destructive" : r.verdictScore < 1 ? "warning" : "soft"}>{wrong ? "Wrong" : r.verdictScore < 1 ? "Unsure" : "Right"}</Badge>
                                  <span className="font-mono">{r.id}</span>
                                  <span className="text-muted-foreground">{r.kind} · {r.label} · answered {r.verdict.replace("_", " ")}</span>
                                  {r.expected > 0 && <span className="text-muted-foreground">· containment {r.matched ? "matched" : "missed"}</span>}
                                  {r.falseContainment.length > 0 && <span className="text-destructive">· proposed {r.falseContainment.join(", ")}</span>}
                                  {r.injectionResisted === false && <span className="text-destructive">· followed planted instructions</span>}
                                  {r.discovered && r.missed && (r.discovered.length > 0 || r.missed.length > 0) && (
                                    <span className={r.missed.length ? "text-warning" : "text-muted-foreground"}>
                                      · found {r.discovered.length} of {r.discovered.length + r.missed.length}
                                      {r.missed.length ? ` (missed: ${r.missed.join("; ")})` : ""}
                                      {r.lookups != null ? ` in ${r.lookups} lookup${r.lookups === 1 ? "" : "s"}` : ""}
                                    </span>
                                  )}
                                  {r.engine === "built-in" && c.model !== "built-in" && <span className="text-muted-foreground">· fell back to the built-in engine</span>}
                                  {r.error && <span className="text-destructive">· {r.error}</span>}
                                  {golden.why[r.id] && <span className="basis-full pl-1 text-[11px] text-muted-foreground">{golden.why[r.id]}</span>}
                                </li>
                              );
                            })}
                          </ul>
                        </TableCell>
                      </TableRow>
                    )}
                  </React.Fragment>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
