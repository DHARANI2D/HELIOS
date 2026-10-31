"use client";

import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { deleteRuleAction, removeTuningAction, setRuleStatusAction } from "@/app/(app)/detections/actions";
import { Button } from "@/components/ui/button";
import { unwrap } from "@/lib/action-result";

export function RuleControls({ id, status, informational }: { id: string; status: "TESTING" | "ACTIVE" | "DISABLED"; informational: boolean }) {
  const router = useRouter();
  const onError = (e: Error) => toast.error(e.message);
  const set = useMutation({ mutationFn: (s: string) => unwrap(setRuleStatusAction(id, s)), onSuccess: (_r, s) => { toast.success(s === "ACTIVE" ? "Live: matches now open cases" : s === "TESTING" ? "Back in testing" : "Disabled"); router.refresh(); }, onError });
  const del = useMutation({ mutationFn: () => unwrap(deleteRuleAction(id)), onSuccess: () => { toast.success("Rule deleted"); router.refresh(); }, onError });
  const busy = set.isPending || del.isPending;
  return (
    <div className="flex flex-wrap justify-end gap-1">
      {busy && <Loader2 className="size-4 animate-spin" />}
      {status !== "ACTIVE" && !informational && <Button size="sm" variant="outline" className="h-7 text-xs" disabled={busy} onClick={() => set.mutate("ACTIVE")}>Go live</Button>}
      {status !== "TESTING" && <Button size="sm" variant="ghost" className="h-7 text-xs" disabled={busy} onClick={() => set.mutate("TESTING")}>Test</Button>}
      {status !== "DISABLED" && <Button size="sm" variant="ghost" className="h-7 text-xs" disabled={busy} onClick={() => set.mutate("DISABLED")}>Disable</Button>}
      <Button size="icon" variant="ghost" className="size-7" aria-label="Delete rule" disabled={busy} onClick={() => { if (confirm("Delete this rule?")) del.mutate(); }}><Trash2 /></Button>
    </div>
  );
}

export function RemoveTuning({ id }: { id: string }) {
  const router = useRouter();
  const del = useMutation({ mutationFn: () => unwrap(removeTuningAction(id)), onSuccess: () => { toast.success("Tuning removed"); router.refresh(); }, onError: (e: Error) => toast.error(e.message) });
  return <Button size="icon" variant="ghost" className="size-7" aria-label="Remove tuning" disabled={del.isPending} onClick={() => del.mutate()}>{del.isPending ? <Loader2 className="animate-spin" /> : <Trash2 />}</Button>;
}
