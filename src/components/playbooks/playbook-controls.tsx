"use client";

import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { History, Loader2, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { deletePlaybookAction, runRetroactiveAction, togglePlaybookAction } from "@/app/(app)/playbooks/actions";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { unwrap } from "@/lib/action-result";

const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Action failed");

export function PlaybookControls({ playbookId, enabled }: { playbookId: string; enabled: boolean }) {
  const router = useRouter();

  const toggle = useMutation({
    mutationFn: (next: boolean) => unwrap(togglePlaybookAction(playbookId, next)),
    onSuccess: () => router.refresh(),
    onError,
  });
  const retro = useMutation({
    mutationFn: () => unwrap(runRetroactiveAction(playbookId)),
    onSuccess: (r) => {
      toast.success(`Checked ${r.analyzed} open cases: ${r.matched} matched${r.queuedForApproval ? `, ${r.queuedForApproval} queued for approval` : ""}`);
      router.refresh();
    },
    onError,
  });
  const remove = useMutation({
    mutationFn: () => unwrap(deletePlaybookAction(playbookId)),
    onSuccess: (r) => {
      toast.success(r.deleted ? "Playbook deleted" : "Playbook has execution history — disabled instead of deleted");
      router.refresh();
    },
    onError,
  });

  return (
    <div className="flex flex-wrap items-center gap-2">
      <label className="flex items-center gap-2 text-xs">
        <Switch checked={enabled} onCheckedChange={(v) => toggle.mutate(v)} disabled={toggle.isPending} />
        {enabled ? "Enabled" : "Disabled"}
      </label>
      <Button size="sm" variant="ghost" onClick={() => retro.mutate()} disabled={retro.isPending || !enabled} title="Apply to existing open cases">
        {retro.isPending ? <Loader2 className="animate-spin" /> : <History />}
        Run on open cases
      </Button>
      <Button
        size="sm"
        variant="ghost"
        onClick={() => {
          if (confirm("Delete this playbook? Playbooks with execution history are disabled instead.")) remove.mutate();
        }}
        disabled={remove.isPending}
      >
        <Trash2 /> Delete
      </Button>
    </div>
  );
}
