"use client";

import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";

import { setDetectorEnabledAction } from "@/app/(app)/mitre/actions";
import { Switch } from "@/components/ui/switch";
import { unwrap } from "@/lib/action-result";

export function DetectorToggle({ name, enabled, canTune }: { name: string; enabled: boolean; canTune: boolean }) {
  const router = useRouter();
  const mut = useMutation({
    mutationFn: (on: boolean) => unwrap(setDetectorEnabledAction(name, on)),
    onSuccess: (_, on) => {
      toast.success(`${name} ${on ? "enabled" : "switched off"}`);
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  return <Switch checked={enabled} onCheckedChange={(on) => mut.mutate(on)} disabled={!canTune || mut.isPending} aria-label={`${name} enabled`} />;
}
