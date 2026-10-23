"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, MessageSquarePlus, UserCheck, UserMinus } from "lucide-react";
import { toast } from "sonner";
import type { CaseSeverity, CaseStatus } from "@prisma/client";

import {
  addCaseNoteAction,
  assignCaseAction,
  setCaseSeverityAction,
  setCaseStatusAction,
} from "@/app/(app)/cases/actions";
import { Button } from "@/components/ui/button";
import { NativeSelect } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { CASE_STATUSES, CASE_STATUS_LABEL } from "@/lib/cases/labels";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";

interface CaseActionsProps {
  caseId: string;
  status: CaseStatus;
  severity: CaseSeverity;
  assignedToMe: boolean;
}

export function CaseActions({ caseId, status, severity, assignedToMe }: CaseActionsProps) {
  const router = useRouter();
  const [note, setNote] = React.useState("");

  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Update failed");
  const done = (msg: string) => () => {
    toast.success(msg);
    router.refresh();
  };

  const statusMut = useMutation({ mutationFn: (s: CaseStatus) => setCaseStatusAction(caseId, s), onSuccess: done("Status updated"), onError });
  const severityMut = useMutation({ mutationFn: (s: CaseSeverity) => setCaseSeverityAction(caseId, s), onSuccess: done("Severity updated"), onError });
  const assignMut = useMutation({ mutationFn: () => assignCaseAction(caseId, !assignedToMe), onSuccess: done(assignedToMe ? "Unassigned" : "Assigned to you"), onError });
  const noteMut = useMutation({
    mutationFn: () => addCaseNoteAction(caseId, note),
    onSuccess: () => {
      setNote("");
      done("Note added")();
    },
    onError,
  });

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3">
        <div className="grid gap-1.5">
          <Label htmlFor="case-status" className="text-xs">Status</Label>
          <NativeSelect id="case-status" value={status} disabled={statusMut.isPending} onChange={(e) => statusMut.mutate(e.target.value as CaseStatus)}>
            {CASE_STATUSES.map((s) => (
              <option key={s} value={s}>{CASE_STATUS_LABEL[s]}</option>
            ))}
          </NativeSelect>
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="case-severity" className="text-xs">Severity</Label>
          <NativeSelect id="case-severity" value={severity} disabled={severityMut.isPending} onChange={(e) => severityMut.mutate(e.target.value as CaseSeverity)}>
            {SEVERITY_ORDER.map((s) => (
              <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>
            ))}
          </NativeSelect>
        </div>
      </div>
      <Button variant="outline" size="sm" onClick={() => assignMut.mutate()} disabled={assignMut.isPending}>
        {assignedToMe ? <UserMinus /> : <UserCheck />}
        {assignedToMe ? "Unassign me" : "Assign to me"}
      </Button>
      <div className="grid gap-2">
        <Textarea value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add an analyst note to the timeline…" className="min-h-20 text-sm" />
        <Button size="sm" onClick={() => noteMut.mutate()} disabled={noteMut.isPending || !note.trim()}>
          {noteMut.isPending ? <Loader2 className="animate-spin" /> : <MessageSquarePlus />}
          Add note
        </Button>
      </div>
    </div>
  );
}
