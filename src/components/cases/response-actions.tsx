"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Bot, Check, CheckCheck, Hand, Loader2, Plus, Undo2, UserRound, X } from "lucide-react";
import { toast } from "sonner";

import { completeManualActionAction, decideResponseActionAction, requestResponseAction, rollbackResponseActionAction } from "@/app/(app)/cases/actions";
import { formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";

export interface ResponseActionView {
  id: string;
  actionType: string;
  label: string;
  target: string | null;
  source: string;
  status: string;
  rationale: string | null;
  policyReason: string | null;
  confidence: number | null;
  summary: string | null;
  manualBy: string | null; // who confirmed doing it by hand
  rollbackable: boolean;
  createdAt: string;
}

const STATUS_VARIANT: Record<string, "warning" | "success" | "destructive" | "outline" | "soft" | "secondary"> = {
  PENDING_APPROVAL: "warning",
  MANUAL_REQUIRED: "warning",
  EXECUTED: "success",
  FAILED: "destructive",
  BLOCKED: "destructive",
  REJECTED: "outline",
  SUGGESTED: "soft",
  ROLLED_BACK: "secondary",
};

const STATUS_LABEL: Record<string, string> = {
  PENDING_APPROVAL: "Awaiting approval",
  MANUAL_REQUIRED: "Do by hand",
  EXECUTED: "Executed",
  FAILED: "Failed",
  BLOCKED: "Blocked by guardrail",
  REJECTED: "Rejected",
  SUGGESTED: "Suggested",
  ROLLED_BACK: "Rolled back",
};

interface Props {
  caseId: string;
  actions: ResponseActionView[];
  canApprove: boolean;
  canRequest: boolean;
  requestable: Array<{ value: string; label: string; targets: string[] }>;
  now: string;
}

export function ResponseActions({ caseId, actions, canApprove, canRequest, requestable, now }: Props) {
  const router = useRouter();
  const nowDate = React.useMemo(() => new Date(now), [now]);
  const [type, setType] = React.useState(requestable[0]?.value ?? "ISOLATE_HOST");
  const [target, setTarget] = React.useState("");
  const [rationale, setRationale] = React.useState("");
  const [open, setOpen] = React.useState(false);
  const options = requestable.find((r) => r.value === type)?.targets ?? [];

  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Action failed");
  const refresh = (msg: string) => {
    toast.success(msg);
    router.refresh();
  };

  const decide = useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: "approved" | "rejected" }) => decideResponseActionAction(id, decision),
    onSuccess: (r) => refresh(r.status === "REJECTED" ? "Rejected" : r.status === "EXECUTED" ? "Approved and executed" : `Status: ${r.status.toLowerCase()}`),
    onError,
  });
  const rollback = useMutation({
    mutationFn: (id: string) => rollbackResponseActionAction(id),
    onSuccess: (r) => refresh(r.status === "MANUAL_REQUIRED" ? "Rollback recorded — carry it out by hand, then mark it done" : "Rolled back"),
    onError,
  });
  const [confirming, setConfirming] = React.useState<string | null>(null);
  const [doneNote, setDoneNote] = React.useState("");
  const markDone = useMutation({
    mutationFn: (id: string) => completeManualActionAction(id, doneNote),
    onSuccess: () => {
      setConfirming(null);
      setDoneNote("");
      refresh("Marked as done");
    },
    onError,
  });
  const request = useMutation({
    mutationFn: () => requestResponseAction(caseId, { actionType: type, target: target || options[0] || "", rationale }),
    onSuccess: (r) => {
      setTarget("");
      setRationale("");
      setOpen(false);
      refresh(r.status === "EXECUTED" ? "Executed" : r.status === "MANUAL_REQUIRED" ? "No connector — carry it out by hand, then mark it done" : "Requested — waiting for approval");
    },
    onError,
  });

  return (
    <div className="flex flex-col gap-3">
      {actions.length === 0 && <p className="text-sm text-muted-foreground">No containment proposed or requested yet.</p>}
      <ul className="flex flex-col gap-2">
        {actions.map((a) => (
          <li key={a.id} className={cn("rounded-lg border p-3", (a.status === "PENDING_APPROVAL" || a.status === "MANUAL_REQUIRED") && "border-warning/50 bg-warning/5")}>
            <div className="flex flex-wrap items-center gap-2">
              {a.source === "ai" ? <Bot className="size-3.5 text-chart-4" /> : <UserRound className="size-3.5 text-muted-foreground" />}
              <span className="text-sm font-medium">{a.label}</span>
              {a.target && <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] break-all">{a.target}</code>}
              <Badge variant={STATUS_VARIANT[a.status] ?? "outline"} className="ml-auto">{STATUS_LABEL[a.status] ?? a.status}</Badge>
            </div>
            {a.rationale && <p className="mt-1 text-xs text-muted-foreground">{a.rationale}</p>}
            <p className="mt-1 text-[11px] text-muted-foreground">
              {a.source === "ai" ? "AI recommendation" : "Analyst request"}
              {a.confidence != null && ` · ${Math.round(a.confidence * 100)}% confidence`} · {formatRelative(new Date(a.createdAt), nowDate)}
              {a.policyReason && <> · <span className="text-foreground/80">{a.policyReason}</span></>}
            </p>
            {a.summary && (
              <p className={cn("mt-1 text-xs", a.status === "FAILED" ? "text-destructive" : "text-foreground/80")}>
                {a.summary}
                {a.manualBy && <span className="text-muted-foreground"> — done by hand, confirmed by {a.manualBy}</span>}
              </p>
            )}
            {canApprove && a.status === "MANUAL_REQUIRED" && (
              confirming === a.id ? (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <Input value={doneNote} onChange={(e) => setDoneNote(e.target.value)} className="h-7 min-w-56 flex-1 text-xs" aria-label="What you did" autoFocus />
                  <Button size="sm" className="h-7" onClick={() => markDone.mutate(a.id)} disabled={markDone.isPending || doneNote.trim().length < 3}>
                    {markDone.isPending ? <Loader2 className="animate-spin" /> : <CheckCheck />} Confirm done
                  </Button>
                  <Button size="sm" variant="ghost" className="h-7" onClick={() => setConfirming(null)}>Cancel</Button>
                  <p className="w-full text-[11px] text-muted-foreground">Say what you did and where (e.g. the console and ticket) — it goes on the case record.</p>
                </div>
              ) : (
                <Button size="sm" variant="outline" className="mt-2 h-7" onClick={() => { setConfirming(a.id); setDoneNote(""); }}>
                  <Hand /> Mark as done
                </Button>
              )
            )}
            {canApprove && (a.status === "PENDING_APPROVAL" || a.status === "SUGGESTED") && (
              <div className="mt-2 flex gap-1.5">
                <Button size="sm" className="h-7" onClick={() => decide.mutate({ id: a.id, decision: "approved" })} disabled={decide.isPending}>
                  {decide.isPending && decide.variables?.id === a.id && decide.variables.decision === "approved" ? <Loader2 className="animate-spin" /> : <Check />}
                  {a.status === "SUGGESTED" ? "Run it" : "Approve"}
                </Button>
                <Button size="sm" variant="outline" className="h-7" onClick={() => decide.mutate({ id: a.id, decision: "rejected" })} disabled={decide.isPending}>
                  <X /> {a.status === "SUGGESTED" ? "Dismiss" : "Reject"}
                </Button>
              </div>
            )}
            {canApprove && a.status === "EXECUTED" && a.rollbackable && (
              <Button size="sm" variant="ghost" className="mt-1 h-7 px-2 text-xs" onClick={() => rollback.mutate(a.id)} disabled={rollback.isPending}>
                {rollback.isPending && rollback.variables === a.id ? <Loader2 className="animate-spin" /> : <Undo2 />}
                Roll back
              </Button>
            )}
          </li>
        ))}
      </ul>

      {canRequest && requestable.length > 0 && (
        <div className="rounded-lg border border-dashed p-3">
          {!open ? (
            <Button size="sm" variant="ghost" onClick={() => setOpen(true)}>
              <Plus /> Request containment
            </Button>
          ) : (
            <div className="flex flex-col gap-2">
              <div className="grid gap-2 sm:grid-cols-2">
                <NativeSelect value={type} onChange={(e) => { setType(e.target.value); setTarget(""); }} aria-label="Action">
                  {requestable.map((r) => (
                    <option key={r.value} value={r.value}>{r.label}</option>
                  ))}
                </NativeSelect>
                {options.length > 0 ? (
                  <NativeSelect value={target || options[0]} onChange={(e) => setTarget(e.target.value)} aria-label="Target">
                    {options.map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </NativeSelect>
                ) : (
                  <Input value={target} onChange={(e) => setTarget(e.target.value)} aria-label="Target (host, IP, account…)" />
                )}
              </div>
              <Input value={rationale} onChange={(e) => setRationale(e.target.value)} aria-label="Why? (shown to the approver)" />
              <p className="-mt-1 text-[11px] text-muted-foreground">Target, then why — the reason is shown to the approver.</p>
              <div className="flex gap-2">
                <Button size="sm" onClick={() => request.mutate()} disabled={request.isPending || !(target || options[0])}>
                  {request.isPending ? <Loader2 className="animate-spin" /> : <Check />}
                  {canApprove ? "Run now" : "Request approval"}
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
