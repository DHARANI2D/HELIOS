"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { CheckCircle2, Circle, Loader2, Plus, SkipForward, X } from "lucide-react";
import { toast } from "sonner";

import { attachRunbookAction, removeCaseRunbookAction, setStepAction } from "@/app/(app)/runbooks/actions";
import { progressOf, type Progress, type RunbookStep } from "@/lib/runbooks/match";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { NativeSelect } from "@/components/ui/native-select";
import { unwrap } from "@/lib/action-result";

const onError = (e: Error) => toast.error(e.message);

export interface CaseRunbookView {
  id: string;
  title: string;
  version: number;
  attachedBy: string;
  steps: RunbookStep[];
  progress: Progress;
}

function Step({ cr, step, canWork }: { cr: CaseRunbookView; step: RunbookStep; canWork: boolean }) {
  const router = useRouter();
  const state = cr.progress[step.id];
  const set = useMutation({
    mutationFn: (change: { state: "done" | "skipped" | "open"; note?: string }) => unwrap(setStepAction(cr.id, step.id, change)),
    onSuccess: () => router.refresh(),
    onError,
  });
  const skip = () => {
    const note = prompt(`Why skip "${step.title}"?`);
    if (note) set.mutate({ state: "skipped", note });
  };
  return (
    <li className="flex items-start gap-2 py-1.5">
      <button type="button" aria-label={state ? `Reopen ${step.title}` : `Mark ${step.title} done`} disabled={!canWork || set.isPending} onClick={() => set.mutate({ state: state ? "open" : "done" })} className="mt-0.5 disabled:opacity-60">
        {set.isPending ? <Loader2 className="size-4 animate-spin" /> : state?.skipped ? <SkipForward className="size-4 text-muted-foreground" /> : state ? <CheckCircle2 className="size-4 text-success" /> : <Circle className="size-4 text-muted-foreground" />}
      </button>
      <div className="min-w-0 flex-1">
        <p className={`text-sm ${state ? "text-muted-foreground" : ""} ${state?.skipped ? "line-through" : ""}`}>
          {step.title} {step.required && !state && <Badge variant="outline" className="ml-1 text-[10px]">required</Badge>}
        </p>
        {step.detail && !state && <p className="text-xs text-muted-foreground">{step.detail}</p>}
        {state && <p className="text-[11px] text-muted-foreground">{state.skipped ? "Skipped" : "Done"} by {state.by}{state.note ? `: ${state.note}` : ""}</p>}
      </div>
      {canWork && !state && <Button size="sm" variant="ghost" className="h-6 px-2 text-[11px]" disabled={set.isPending} onClick={skip}>Skip</Button>}
    </li>
  );
}

export function CaseRunbooks({ caseId, runbooks, available, canWork }: { caseId: string; runbooks: CaseRunbookView[]; available: Array<{ id: string; title: string }>; canWork: boolean }) {
  const router = useRouter();
  const [pick, setPick] = React.useState("");
  const attach = useMutation({ mutationFn: () => unwrap(attachRunbookAction(caseId, pick)), onSuccess: () => { setPick(""); router.refresh(); }, onError });
  const remove = useMutation({ mutationFn: (id: string) => unwrap(removeCaseRunbookAction(id)), onSuccess: () => router.refresh(), onError });
  const unused = available.filter((a) => !runbooks.some((r) => r.title === a.title));
  return (
    <div className="flex flex-col gap-4">
      {runbooks.length === 0 && <p className="text-sm text-muted-foreground">No runbook matched this case.</p>}
      {runbooks.map((cr) => {
        const p = progressOf(cr.steps, cr.progress);
        return (
          <div key={cr.id} className="rounded-md border p-3">
            <div className="flex items-center justify-between gap-2">
              <p className="text-sm font-medium">{cr.title} <span className="text-xs font-normal text-muted-foreground">v{cr.version} · {cr.attachedBy === "matched" ? "matched" : `added by ${cr.attachedBy}`}</span></p>
              <div className="flex items-center gap-1">
                <Badge variant={p.complete ? "success" : p.requiredOpen.length ? "warning" : "outline"}>{p.done}/{p.total}</Badge>
                {canWork && <Button size="icon" variant="ghost" className="size-6" aria-label={`Take ${cr.title} off the case`} onClick={() => remove.mutate(cr.id)}><X className="size-3.5" /></Button>}
              </div>
            </div>
            <ul className="mt-1 divide-y">{cr.steps.map((s) => <Step key={s.id} cr={cr} step={s} canWork={canWork} />)}</ul>
          </div>
        );
      })}
      {canWork && unused.length > 0 && (
        <div className="flex gap-2">
          <NativeSelect aria-label="Add a runbook" className="h-8 text-xs" value={pick} onChange={(e) => setPick(e.target.value)}>
            <option value="">Add a runbook…</option>
            {unused.map((r) => <option key={r.id} value={r.id}>{r.title}</option>)}
          </NativeSelect>
          <Button size="sm" variant="outline" disabled={!pick || attach.isPending} onClick={() => attach.mutate()}>{attach.isPending ? <Loader2 className="animate-spin" /> : <Plus />} Add</Button>
        </div>
      )}
    </div>
  );
}
