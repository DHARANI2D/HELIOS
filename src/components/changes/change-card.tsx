"use client";

import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Check, CircleDashed, Loader2, Undo2, X } from "lucide-react";
import { toast } from "sonner";

import { approveChangeAction, rejectChangeAction, withdrawChangeAction } from "@/app/(app)/changes/actions";
import type { ChangeView } from "@/lib/changes/view";
import { unwrap } from "@/lib/action-result";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";

const STATUS = {
  PENDING: { label: "Waiting for approval", variant: "warning" },
  APPLIED: { label: "In effect", variant: "success" },
  REJECTED: { label: "Turned down", variant: "destructive" },
  WITHDRAWN: { label: "Withdrawn", variant: "secondary" },
  STALE: { label: "Lapsed", variant: "secondary" },
} as const;

const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" }) : "");

function Slot({ label, byName, at, note, waiting }: { label: string; byName: string | null; at: string | null; note: string | null; waiting: boolean }) {
  return (
    <div className={cn("flex min-w-0 flex-1 flex-col gap-0.5 rounded-md border p-2 text-xs", byName ? "border-emerald-500/40 bg-emerald-500/5" : "border-dashed")}>
      <span className="flex items-center gap-1 font-medium">
        {byName ? <Check className="size-3.5 text-emerald-600" /> : <CircleDashed className="size-3.5 text-muted-foreground" />} {label}
      </span>
      {byName ? (
        <span className="text-muted-foreground">
          {byName} · {when(at)}
          {note ? <span className="block break-words">{note}</span> : null}
        </span>
      ) : (
        <span className="text-muted-foreground">{waiting ? "Waiting" : "Not given"}</span>
      )}
    </div>
  );
}

const OUTCOMES: Array<[string, string]> = [["EXECUTED", "Automatic"], ["PENDING_APPROVAL", "Held for approval"], ["SUGGESTED", "Suggestion only"], ["BLOCKED", "Blocked"]];

// A rulebook version's review: what changes against the version in force,
// and how the last 30 days of AI proposals would have gone under it.
function Impact({ impact }: { impact: NonNullable<ChangeView["impact"]> }) {
  const shown = impact.diff.slice(0, 12);
  return (
    <div className="grid gap-2 md:grid-cols-2">
      <div className="min-w-0 rounded-md border p-2 text-xs">
        <p className="font-medium">What changes {impact.againstVersion ? `against v${impact.againstVersion} in force` : "(no version in force yet)"}</p>
        {impact.diff.length === 0 ? (
          <p className="text-muted-foreground">Nothing: the same rules as in force.</p>
        ) : (
          <ul className="mt-1 flex flex-col gap-0.5 font-mono text-[11px]">
            {shown.map((d, i) => (
              <li key={i} className="break-words">
                <span className={cn(d.kind === "added" ? "text-emerald-600" : d.kind === "removed" ? "text-destructive" : "text-amber-600")}>{d.kind === "added" ? "+" : d.kind === "removed" ? "−" : "~"}</span> {d.path}
                {d.kind === "changed" ? `: ${d.before} → ${d.after}` : d.kind === "added" ? `: ${d.after ?? ""}` : `: ${d.before ?? ""}`}
              </li>
            ))}
            {impact.diff.length > shown.length && <li className="text-muted-foreground">and {impact.diff.length - shown.length} more (see Versions on the rulebook page)</li>}
          </ul>
        )}
      </div>
      <div className="min-w-0 rounded-md border p-2 text-xs">
        <p className="font-medium">Dry run{impact.dryRun ? `: last ${impact.dryRun.days} days, ${impact.dryRun.total} AI proposal${impact.dryRun.total === 1 ? "" : "s"}` : ""}</p>
        {!impact.dryRun ? (
          <p className="text-muted-foreground">Not available.</p>
        ) : impact.dryRun.total === 0 ? (
          <p className="text-muted-foreground">No AI containment proposals for this client yet.</p>
        ) : (
          <>
            <table className="mt-1 w-full">
              <thead className="text-left text-muted-foreground"><tr><th className="font-normal">Outcome</th><th className="text-right font-normal">At the time</th><th className="text-right font-normal">Under this version</th></tr></thead>
              <tbody>
                {OUTCOMES.map(([k, label]) => (
                  <tr key={k}><td>{label}</td><td className="text-right tabular-nums">{impact.dryRun!.then[k] ?? 0}</td><td className={cn("text-right tabular-nums", (impact.dryRun!.now[k] ?? 0) !== (impact.dryRun!.then[k] ?? 0) && "font-semibold")}>{impact.dryRun!.now[k] ?? 0}</td></tr>
                ))}
              </tbody>
            </table>
            <p className="mt-1 text-muted-foreground">{impact.dryRun.changed} decision{impact.dryRun.changed === 1 ? "" : "s"} would change.</p>
          </>
        )}
      </div>
    </div>
  );
}

export function ChangeCard({ change, compact = false }: { change: ChangeView; compact?: boolean }) {
  const router = useRouter();
  const [mode, setMode] = React.useState<null | "client" | "helios" | "reject">(null);
  const [note, setNote] = React.useState("");
  const [ack, setAck] = React.useState(false);
  const done = (msg: string) => {
    toast.success(msg);
    setMode(null);
    setNote("");
    setAck(false);
    router.refresh();
  };
  const fail = (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed");
  const approve = useMutation({ mutationFn: (side: "client" | "helios") => unwrap(approveChangeAction(change.id, { side, note, acknowledged: ack })), onSuccess: (r) => done(r.applied ? "Approved: the change is now in effect" : "Approved: waiting for the other approval"), onError: fail });
  const reject = useMutation({ mutationFn: () => unwrap(rejectChangeAction(change.id, note)), onSuccess: () => done("Turned down"), onError: fail });
  const withdraw = useMutation({ mutationFn: () => unwrap(withdrawChangeAction(change.id)), onSuccess: () => done("Withdrawn"), onError: fail });
  const s = STATUS[change.status];
  const pending = change.status === "PENDING";
  const onBehalf = mode === "client" && change.can.clientOnBehalf;
  const busy = approve.isPending || reject.isPending || withdraw.isPending;

  return (
    <div className="flex flex-col gap-2 rounded-lg border p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-medium break-words">{change.summary}</p>
          <p className="text-xs text-muted-foreground">
            {change.kindLabel}
            {change.tenantName ? ` · ${change.tenantName}` : change.platform ? " · whole platform" : ""} · asked by {change.requestedByName}
            {change.requestedByClient ? " (client)" : ""} · {when(change.requestedAt)}
          </p>
        </div>
        <Badge variant={s.variant}>{s.label}</Badge>
      </div>
      {!compact && <p className="text-xs break-words"><span className="text-muted-foreground">Why: </span>{change.reason}</p>}
      {!compact && change.impact && <Impact impact={change.impact} />}
      <div className="flex flex-wrap gap-2">
        {change.needsClient && <Slot label="Client's approval" byName={change.client.byName} at={change.client.at} note={change.client.note} waiting={pending} />}
        <Slot label={change.platform ? "Second HELIOS approver" : "HELIOS's approval"} byName={change.helios.byName} at={change.helios.at} note={change.helios.note} waiting={pending} />
      </div>
      {!pending && change.decisionNote && (
        <p className="text-xs text-muted-foreground break-words">{change.decidedByName}: {change.decisionNote}</p>
      )}
      {pending && change.blocked && <p className="text-xs text-muted-foreground">{change.blocked}</p>}

      {pending && mode === null && (
        <div className="flex flex-wrap gap-2">
          {change.can.client && (
            <Button size="sm" onClick={() => setMode("client")} disabled={busy}>
              <Check /> {change.can.clientOnBehalf ? "Record the client's approval" : "Approve"}
            </Button>
          )}
          {change.can.helios && (
            <Button size="sm" onClick={() => setMode("helios")} disabled={busy}>
              <Check /> Approve for HELIOS
            </Button>
          )}
          {change.can.reject && (
            <Button size="sm" variant="outline" onClick={() => setMode("reject")} disabled={busy}>
              <X /> Turn down
            </Button>
          )}
          {change.can.withdraw && (
            <Button size="sm" variant="ghost" onClick={() => withdraw.mutate()} disabled={busy}>
              {withdraw.isPending ? <Loader2 className="animate-spin" /> : <Undo2 />} Withdraw
            </Button>
          )}
          {change.href && (
            <Button size="sm" variant="ghost" asChild>
              <Link href={change.href}>Open</Link>
            </Button>
          )}
        </div>
      )}

      {pending && (mode === "client" || mode === "helios") && (
        <div className="flex flex-col gap-2 rounded-md border border-primary/40 bg-primary/5 p-2">
          <p className="text-xs text-muted-foreground">
            {onBehalf
              ? "Only with the client's instruction. Record who approved it, when and how (e.g. email from the CISO on 25 Oct); it goes into the audit chain. Another HELIOS approver must then give HELIOS's approval."
              : mode === "helios"
                ? "You confirm HELIOS has reviewed this change. It takes effect once every approval it needs is in; the change's fingerprint goes into the audit chain."
                : "Approving lets this change take effect once HELIOS has approved it too. Your name, the time and the change's fingerprint are recorded."}
          </p>
          <Textarea className="min-h-14 text-xs" value={note} onChange={(e) => setNote(e.target.value)} placeholder={onBehalf ? "Client's instruction (required)" : "Optional note"} aria-label="Approval note" />
          <label className="flex items-center gap-2 text-xs">
            <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
            {onBehalf ? "The client has approved this exact change" : "I've read this change and approve it taking effect"}
          </label>
          <div className="flex gap-2">
            <Button size="sm" onClick={() => approve.mutate(mode)} disabled={busy || !ack || (onBehalf && note.trim().length < 10)}>
              {approve.isPending ? <Loader2 className="animate-spin" /> : <Check />} Approve
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setMode(null)}>Cancel</Button>
          </div>
          <p className="font-mono text-[10px] text-muted-foreground break-all">Fingerprint {change.hash}</p>
        </div>
      )}

      {pending && mode === "reject" && (
        <div className="flex flex-col gap-2 rounded-md border p-2">
          <Textarea className="min-h-14 text-xs" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Why it's turned down" aria-label="Reason" />
          <div className="flex gap-2">
            <Button size="sm" variant="destructive" onClick={() => reject.mutate()} disabled={busy || note.trim().length < 3}>
              {reject.isPending ? <Loader2 className="animate-spin" /> : <X />} Turn down
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setMode(null)}>Cancel</Button>
          </div>
        </div>
      )}
    </div>
  );
}
