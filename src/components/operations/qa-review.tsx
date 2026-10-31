"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Send } from "lucide-react";
import { toast } from "sonner";

import { submitQaReviewAction } from "@/app/(app)/operations/actions";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { unwrap } from "@/lib/action-result";

export interface QaAction {
  id: string;
  label: string;
  target: string | null;
  status: string;
  level: string | null;
}

function Choice({ name, value, onChange, options }: { name: string; value: string | null; onChange: (v: string) => void; options: Array<[string, string]> }) {
  return (
    <div className="flex gap-1" role="radiogroup" aria-label={name}>
      {options.map(([v, label]) => (
        <button key={v} type="button" role="radio" aria-checked={value === v} onClick={() => onChange(v)} className={`rounded-md border px-2 py-0.5 text-xs ${value === v ? (v === "wrong" || v === "no" ? "border-destructive bg-destructive/10" : "border-success bg-success/10") : "hover:bg-muted"}`}>
          {label}
        </button>
      ))}
    </div>
  );
}

// The reviewer's calls: per action the AI ran on its own, and on its verdict.
export function QaReviewForm({ reviewId, actions, verdict }: { reviewId: string; actions: QaAction[]; verdict: string | null }) {
  const router = useRouter();
  const [calls, setCalls] = React.useState<Record<string, string>>({});
  const [verdictCall, setVerdictCall] = React.useState<string | null>(null);
  const [notes, setNotes] = React.useState("");
  const ready = actions.every((a) => calls[a.id]) && (!verdict || verdictCall);
  const submit = useMutation({
    mutationFn: () => unwrap(submitQaReviewAction(reviewId, { actions: calls, verdictRight: verdict ? verdictCall === "yes" : null, notes })),
    onSuccess: (outcome) => { toast.success(outcome === "agree" ? "Reviewed: the AI got it right" : outcome === "partly" ? "Reviewed: partly right" : "Reviewed: the AI got it wrong"); router.refresh(); },
    onError: (e: Error) => toast.error(e.message),
  });
  return (
    <div className="flex flex-col gap-3 text-sm">
      {actions.map((a) => (
        <div key={a.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-2">
          <span className="text-xs">
            <span className="font-medium">{a.label}</span> {a.target && <span className="font-mono">{a.target}</span>}
            <span className="text-muted-foreground"> · {a.status.toLowerCase().replace("_", " ")}{a.level ? ` · level ${a.level}` : ""}</span>
          </span>
          <Choice name={`Should ${a.label} have run?`} value={calls[a.id] ?? null} onChange={(v) => setCalls((c) => ({ ...c, [a.id]: v }))} options={[["right", "Should have run"], ["wrong", "Shouldn't have"]]} />
        </div>
      ))}
      {verdict && (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-2">
          <span className="text-xs">The AI&apos;s verdict: <span className="font-medium">{verdict.replace("_", " ")}</span></span>
          <Choice name="Was the verdict right?" value={verdictCall} onChange={setVerdictCall} options={[["yes", "Right"], ["no", "Wrong"]]} />
        </div>
      )}
      <div className="grid gap-1">
        <Label htmlFor={`qa-notes-${reviewId}`} className="text-xs">Notes (what it should have done)</Label>
        <Textarea id={`qa-notes-${reviewId}`} className="min-h-16 text-xs" value={notes} onChange={(e) => setNotes(e.target.value)} />
      </div>
      <p className="text-xs text-muted-foreground">If the case itself was closed wrongly, reopen it and close it with the right disposition: the disposition is what the AI is measured against.</p>
      <div><Button size="sm" disabled={!ready || submit.isPending} onClick={() => submit.mutate()}>{submit.isPending ? <Loader2 className="animate-spin" /> : <Send />} Submit review</Button></div>
    </div>
  );
}
