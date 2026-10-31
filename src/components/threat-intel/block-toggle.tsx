"use client";

import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Ban, Loader2, Undo2 } from "lucide-react";
import { toast } from "sonner";

import { setBlockedAction } from "@/app/(app)/threat-intel/actions";
import { Button } from "@/components/ui/button";
import { unwrap } from "@/lib/action-result";

export function BlockToggle({ indicatorId, blocked }: { indicatorId: string; blocked: boolean }) {
  const router = useRouter();
  const toggle = useMutation({
    mutationFn: () => unwrap(setBlockedAction(indicatorId, !blocked)),
    onSuccess: () => {
      toast.success(blocked ? "Removed from blocklist" : "Added to blocklist");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Update failed"),
  });
  return (
    <Button size="sm" variant={blocked ? "outline" : "ghost"} className="h-7" onClick={() => toggle.mutate()} disabled={toggle.isPending}>
      {toggle.isPending ? <Loader2 className="animate-spin" /> : blocked ? <Undo2 /> : <Ban />}
      {blocked ? "Unblock" : "Block"}
    </Button>
  );
}
