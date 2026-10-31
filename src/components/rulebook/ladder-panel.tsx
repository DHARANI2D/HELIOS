"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, Check, Eye, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { lowerLevelAction, proposePromotionAction, resumeAutomationAction, startShadowModeAction } from "@/app/(app)/rulebook/ladder-actions";
import { DEMOTION, LEVELS, PROMOTION } from "@/lib/shadow/ladder";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { unwrap } from "@/lib/action-result";

export interface LadderRow {
  actionType: string;
  label: string;
  level: number;
  reason: string | null;
  changedBy: string;
  proposedLevel: number | null;
  month: { decisions: number; agreed: number; falseContainments: number; criticalFalseContainments: number; misses: number };
  week: { decisions: number; agreed: number };
  eligible: boolean;
  notYet: string[];
  // What else caps this action for the client (plan, consent, rulebook), if lower.
  cappedBy: string | null;
}

interface Props {
  tenantId: string;
  started: boolean;
  rows: LadderRow[];
  verdicts: { scored: number; agreed: number };
  canManage: boolean;
  canApprove: boolean;
  isClient: boolean;
}

const pct = (a: number, b: number) => (b ? `${Math.round((a / b) * 100)}%` : "—");

function useAct<T>(fn: (v: T) => Promise<unknown>, msg: string) {
  const router = useRouter();
  return useMutation({ mutationFn: fn, onSuccess: () => { toast.success(msg); router.refresh(); }, onError: (e) => toast.error(e instanceof Error ? e.message : "Failed") });
}

export function LadderPanel({ tenantId, started, rows, verdicts, canManage, canApprove, isClient }: Props) {
  const [note, setNote] = React.useState("");
  const start = useAct(() => unwrap(startShadowModeAction(tenantId)), "Shadow mode started: the AI observes and is measured against your analysts");
  const lower = useAct(({ a, level }: { a: string; level: number }) => unwrap(lowerLevelAction(tenantId, a, level, note || "Lowered by the SOC")), "Level lowered");
  const propose = useAct((a: string) => unwrap(proposePromotionAction(tenantId, a)), "Promotion proposed: it takes effect once the client and HELIOS approve it");

  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-2 sm:grid-cols-5">
        {LEVELS.map((l) => (
          <div key={l.level} className="rounded-lg border p-2 text-xs">
            <p className="font-semibold">L{l.level} {l.name}</p>
            <p className="text-muted-foreground">AI: {l.ai}</p>
            <p className="text-muted-foreground">People: {l.human}</p>
          </div>
        ))}
      </div>
      <p className="text-xs text-muted-foreground">
        Autonomy is earned per action from how often the AI&apos;s decisions match the analysts&apos; dispositions. A promotion needs {PROMOTION.minDecisions} scored decisions in {PROMOTION.windowDays} days, {Math.round(PROMOTION.minAgreement * 100)}% agreement, no wrong containment of a critical asset, and the client&apos;s approval. A week below {Math.round(DEMOTION.minAgreement * 100)}% drops a level automatically; a critical mistake drops it to suggestions. Plan, consent and the rulebook still cap every level.
      </p>

      {!started ? (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-dashed p-4">
          <p className="text-sm">The ladder hasn&apos;t started for this client: only the plan, consent and rulebook limit the AI.</p>
          {canManage && (
            <Button size="sm" onClick={() => start.mutate(undefined)} disabled={start.isPending}>
              {start.isPending ? <Loader2 className="animate-spin" /> : <Eye />} Start shadow mode (L0 for every action)
            </Button>
          )}
        </div>
      ) : (
        <>
          <div className="flex flex-wrap gap-4 text-xs">
            <p><span className="font-medium">Verdicts:</span> {verdicts.agreed} of {verdicts.scored} matched the analysts ({pct(verdicts.agreed, verdicts.scored)}) in {PROMOTION.windowDays} days</p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-left text-muted-foreground">
                <tr>
                  <th className="py-1">Action</th>
                  <th>Level</th>
                  <th className="text-right">Decisions ({PROMOTION.windowDays}d)</th>
                  <th className="text-right">Agreement</th>
                  <th className="text-right">Wrong containment</th>
                  <th className="text-right">Missed</th>
                  <th className="text-right">This week</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.actionType} className="border-t align-top">
                    <td className="py-1.5 pr-2 font-medium">{r.label}</td>
                    <td className="pr-2">
                      <Badge variant={r.level === 0 ? "outline" : r.level >= 3 ? "success" : "secondary"}>L{r.level} {LEVELS[r.level].name}</Badge>
                      {r.cappedBy && <p className="mt-0.5 text-[11px] text-muted-foreground">Capped by {r.cappedBy}</p>}
                      {r.reason && <p className="mt-0.5 max-w-48 text-[11px] text-muted-foreground">{r.reason} · {r.changedBy}</p>}
                    </td>
                    <td className="text-right tabular-nums">{r.month.decisions}</td>
                    <td className="text-right tabular-nums">{pct(r.month.agreed, r.month.decisions)}</td>
                    <td className={cn("text-right tabular-nums", r.month.falseContainments > 0 && "text-destructive")}>
                      {r.month.falseContainments}
                      {r.month.criticalFalseContainments > 0 && ` (${r.month.criticalFalseContainments} critical)`}
                    </td>
                    <td className="text-right tabular-nums">{r.month.misses}</td>
                    <td className="text-right tabular-nums">{pct(r.week.agreed, r.week.decisions)}</td>
                    <td className="pl-2">
                      <div className="flex flex-col items-end gap-1">
                        {r.proposedLevel != null ? (
                          <div className="flex flex-col items-end gap-1 rounded-md border border-primary/40 bg-primary/5 p-1.5">
                            <span className="text-[11px]">Proposed: L{r.proposedLevel} {LEVELS[r.proposedLevel].name}</span>
                            <a href="#rule-changes" className="text-[10px] text-muted-foreground underline-offset-2 hover:underline">Needs the client&apos;s and HELIOS&apos;s approval{canApprove ? ": decide below" : ""}</a>
                          </div>
                        ) : (
                          canManage && r.level < 4 && (
                            <Button size="sm" variant="outline" className="h-6 px-2 text-[11px]" onClick={() => propose.mutate(r.actionType)} disabled={propose.isPending || !r.eligible} title={r.eligible ? undefined : r.notYet.join("; ")}>
                              <ArrowUp /> Propose L{r.level + 1}
                            </Button>
                          )
                        )}
                        {!r.eligible && r.level < 4 && r.proposedLevel == null && <span className="max-w-44 text-right text-[10px] text-muted-foreground">{r.notYet[0]}</span>}
                        {canManage && r.level > 0 && (
                          <Button size="sm" variant="ghost" className="h-6 px-2 text-[11px]" onClick={() => lower.mutate({ a: r.actionType, level: r.level - 1 })} disabled={lower.isPending}>
                            <ArrowDown /> Lower to L{r.level - 1}
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {(canManage || canApprove) && (
            <Input className="h-8 text-xs" value={note} onChange={(e) => setNote(e.target.value)} placeholder={isClient ? "Note (optional)" : "Reason for lowering a level"} aria-label="Note for ladder changes" />
          )}
        </>
      )}
    </div>
  );
}

export function ResumeAutomationButton({ tenantId }: { tenantId: string }) {
  const resume = useAct(() => unwrap(resumeAutomationAction(tenantId)), "Automatic containment resumed");
  return (
    <Button size="sm" variant="outline" className="w-fit" onClick={() => resume.mutate(undefined)} disabled={resume.isPending}>
      {resume.isPending ? <Loader2 className="animate-spin" /> : <Check />} Resume automatic containment
    </Button>
  );
}
