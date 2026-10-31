"use client";

import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { DownloadCloud, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { importFeedAction, setFeedEnabledAction } from "@/app/(app)/threat-intel/actions";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { unwrap } from "@/lib/action-result";

export function FeedControls({ id, name, enabled, canManage }: { id: string; name: string; enabled: boolean; canManage: boolean }) {
  const router = useRouter();
  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed");
  const toggle = useMutation({ mutationFn: (on: boolean) => unwrap(setFeedEnabledAction(id, on)), onSuccess: () => router.refresh(), onError });
  const run = useMutation({
    mutationFn: () => unwrap(importFeedAction(id)),
    onSuccess: (r) => {
      toast.success(`${r.name}: ${r.count.toLocaleString()} entries imported`);
      router.refresh();
    },
    onError,
  });
  return (
    <div className="flex items-center justify-end gap-2">
      {canManage && (
        <Button size="sm" variant="ghost" className="h-7" onClick={() => run.mutate()} disabled={run.isPending} title={`Download ${name} now`}>
          {run.isPending ? <Loader2 className="animate-spin" /> : <DownloadCloud />} Import
        </Button>
      )}
      <Switch checked={enabled} disabled={!canManage || toggle.isPending} onCheckedChange={(v) => toggle.mutate(v)} aria-label={`${name} enabled`} />
    </div>
  );
}
