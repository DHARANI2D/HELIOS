"use client";

import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { BellOff, BellRing, CheckCheck, Loader2 } from "lucide-react";
import { toast } from "sonner";
import type { CaseSeverity, CaseStatus } from "@prisma/client";

import { acknowledgeCaseAction, assignCaseAction, setCaseSeverityAction, setCaseStatusAction, setWatchingAction } from "@/app/(app)/cases/actions";
import { Button } from "@/components/ui/button";
import { NativeSelect } from "@/components/ui/native-select";
import { Label } from "@/components/ui/label";
import { CASE_STATUSES, CASE_STATUS_LABEL } from "@/lib/cases/labels";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";

export interface TeamMember {
  id: string;
  name: string;
  role: string;
}

interface TriagePanelProps {
  caseId: string;
  status: CaseStatus;
  severity: CaseSeverity;
  assigneeId: string | null;
  acknowledged: boolean;
  watching: boolean;
  viewerId: string;
  canTriage: boolean;
  canAssignOthers: boolean;
  team: TeamMember[];
}

export function TriagePanel({ caseId, status, severity, assigneeId, acknowledged, watching, viewerId, canTriage, canAssignOthers, team }: TriagePanelProps) {
  const router = useRouter();
  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Update failed");
  const done = (msg: string) => () => {
    toast.success(msg);
    router.refresh();
  };

  const statusMut = useMutation({ mutationFn: (s: CaseStatus) => setCaseStatusAction(caseId, s), onSuccess: done("Status updated"), onError });
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
          <NativeSelect id="case-status" value={status} disabled={!canTriage || statusMut.isPending} onChange={(e) => statusMut.mutate(e.target.value as CaseStatus)}>
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
