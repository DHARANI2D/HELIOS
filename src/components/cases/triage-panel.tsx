"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { BellOff, BellRing, CheckCheck, Loader2 } from "lucide-react";
import { toast } from "sonner";
import type { CaseDisposition, CaseSeverity, CaseStatus } from "@prisma/client";

import { acknowledgeCaseAction, assignCaseAction, setCaseSeverityAction, setCaseStatusAction, setWatchingAction } from "@/app/(app)/cases/actions";
import { Button } from "@/components/ui/button";
import { NativeSelect } from "@/components/ui/native-select";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { CASE_STATUSES, CASE_STATUS_LABEL } from "@/lib/cases/labels";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";

export interface TeamMember {
  id: string;
  name: string;
  role: string;
}

const CLOSING: CaseStatus[] = ["RESOLVED", "FALSE_POSITIVE"];
const DISPOSITIONS: Array<{ value: CaseDisposition; label: string; hint: string }> = [
  { value: "TRUE_POSITIVE", label: "True positive", hint: "A real threat or incident" },
  { value: "BENIGN_TRUE_POSITIVE", label: "Benign true positive", hint: "Real activity, but expected or authorised" },
  { value: "FALSE_POSITIVE", label: "False positive", hint: "The detection was wrong" },
];

interface TriagePanelProps {
  caseId: string;
  status: CaseStatus;
  disposition: { value: CaseDisposition; label: string; reason: string | null } | null;
  // How the AI's decisions on this case compared with the analysts' (shadow mode scoring).
  aiScore: { agreed: number; total: number; falseContainments: number; misses: number } | null;
  severity: CaseSeverity;
  assigneeId: string | null;
  acknowledged: boolean;
  watching: boolean;
  viewerId: string;
  canTriage: boolean;
  canAssignOthers: boolean;
  team: TeamMember[];
}

export function TriagePanel({ caseId, status, disposition, aiScore, severity, assigneeId, acknowledged, watching, viewerId, canTriage, canAssignOthers, team }: TriagePanelProps) {
  const router = useRouter();
  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Update failed");
  const done = (msg: string) => () => {
    toast.success(msg);
    router.refresh();
  };

  const [closing, setClosing] = React.useState<CaseStatus | null>(null);
  const [disp, setDisp] = React.useState<CaseDisposition>("TRUE_POSITIVE");
  const [reason, setReason] = React.useState("");
  const statusMut = useMutation({
    mutationFn: (s: CaseStatus) => setCaseStatusAction(caseId, s, undefined, CLOSING.includes(s) ? { disposition: s === "FALSE_POSITIVE" ? "FALSE_POSITIVE" : disp, reason } : undefined),
    onSuccess: () => {
      setClosing(null);
      setReason("");
      done("Status updated")();
    },
    onError,
  });
  const pickStatus = (s: CaseStatus) => {
    if (!CLOSING.includes(s)) return statusMut.mutate(s);
    setDisp(s === "FALSE_POSITIVE" ? "FALSE_POSITIVE" : "TRUE_POSITIVE");
    setClosing(s);
  };
  const severityMut = useMutation({ mutationFn: (s: CaseSeverity) => setCaseSeverityAction(caseId, s), onSuccess: done("Severity updated"), onError });
  const assignMut = useMutation({ mutationFn: (id: string | null) => assignCaseAction(caseId, id), onSuccess: done("Assignment updated"), onError });
  const ackMut = useMutation({ mutationFn: () => acknowledgeCaseAction(caseId), onSuccess: done("Acknowledged — SLA clock stopped"), onError });
  const watchMut = useMutation({ mutationFn: () => setWatchingAction(caseId, !watching), onSuccess: done(watching ? "Stopped watching" : "Watching — you'll be notified of updates"), onError });

  const assignable = canAssignOthers ? team : team.filter((m) => m.id === viewerId);

  return (
    <div className="flex flex-col gap-4">
      {!acknowledged && canTriage && (
        <Button onClick={() => ackMut.mutate()} disabled={ackMut.isPending} className="w-full">
          {ackMut.isPending ? <Loader2 className="animate-spin" /> : <CheckCheck />}
          Acknowledge
        </Button>
      )}
      <div className="grid grid-cols-2 gap-3">
        <div className="grid gap-1.5">
          <Label htmlFor="case-status" className="text-xs">Status</Label>
          <NativeSelect id="case-status" value={closing ?? status} disabled={!canTriage || statusMut.isPending} onChange={(e) => pickStatus(e.target.value as CaseStatus)}>
            {CASE_STATUSES.map((s) => (
              <option key={s} value={s}>{CASE_STATUS_LABEL[s]}</option>
            ))}
          </NativeSelect>
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="case-severity" className="text-xs">Severity</Label>
          <NativeSelect id="case-severity" value={severity} disabled={!canTriage || severityMut.isPending} onChange={(e) => severityMut.mutate(e.target.value as CaseSeverity)}>
            {SEVERITY_ORDER.map((s) => (
              <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>
            ))}
          </NativeSelect>
        </div>
      </div>
      {closing && (
        <div className="flex flex-col gap-2 rounded-lg border border-primary/40 bg-primary/5 p-3">
          <p className="text-sm font-medium">Close as {closing === "FALSE_POSITIVE" ? "false positive" : "resolved"}</p>
          <div className="grid gap-1.5">
            <Label htmlFor="case-disposition" className="text-xs">Disposition</Label>
            <NativeSelect id="case-disposition" value={disp} disabled={closing === "FALSE_POSITIVE"} onChange={(e) => setDisp(e.target.value as CaseDisposition)}>
              {DISPOSITIONS.filter((d) => closing !== "RESOLVED" || d.value !== "FALSE_POSITIVE").map((d) => (
                <option key={d.value} value={d.value}>{d.label} — {d.hint}</option>
              ))}
            </NativeSelect>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="case-reason" className="text-xs">Why</Label>
            <Textarea id="case-reason" className="min-h-14 text-xs" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="What you found and what was done" />
          </div>
          <p className="text-[11px] text-muted-foreground">Your call is the ground truth the AI&apos;s decisions on this case are measured against.</p>
          <div className="flex gap-2">
            <Button size="sm" onClick={() => statusMut.mutate(closing)} disabled={statusMut.isPending || reason.trim().length < 3}>
              {statusMut.isPending ? <Loader2 className="animate-spin" /> : <CheckCheck />} Close case
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setClosing(null)}>Cancel</Button>
          </div>
        </div>
      )}
      {disposition && !closing && (
        <div className="rounded-lg border p-3 text-xs">
          <p><span className="font-medium">Disposition:</span> {disposition.label}</p>
          {disposition.reason && <p className="mt-0.5 text-muted-foreground">{disposition.reason}</p>}
          {aiScore && (
            <p className="mt-1.5">
              <span className="font-medium">AI against this call:</span> {aiScore.agreed} of {aiScore.total} decisions matched
              {aiScore.falseContainments > 0 && <span className="text-destructive"> · {aiScore.falseContainments} {aiScore.falseContainments === 1 ? "containment" : "containments"} the analysts wouldn&apos;t have done</span>}
              {aiScore.misses > 0 && ` · ${aiScore.misses} action${aiScore.misses === 1 ? "" : "s"} the AI didn't propose`}
            </p>
          )}
        </div>
      )}
      <div className="grid gap-1.5">
        <Label htmlFor="case-assignee" className="text-xs">Assignee</Label>
        <NativeSelect
          id="case-assignee"
          value={assigneeId ?? ""}
          disabled={!canTriage || assignMut.isPending}
          onChange={(e) => assignMut.mutate(e.target.value || null)}
        >
          <option value="">Unassigned</option>
          {assigneeId && !assignable.some((m) => m.id === assigneeId) && <option value={assigneeId}>{team.find((m) => m.id === assigneeId)?.name ?? "Current assignee"}</option>}
          {assignable.map((m) => (
            <option key={m.id} value={m.id}>
              {m.id === viewerId ? `${m.name} (me)` : m.name} · {m.role}
            </option>
          ))}
        </NativeSelect>
      </div>
      <Button variant="outline" size="sm" onClick={() => watchMut.mutate()} disabled={watchMut.isPending}>
        {watching ? <BellOff /> : <BellRing />}
        {watching ? "Stop watching" : "Watch case"}
      </Button>
    </div>
  );
}
