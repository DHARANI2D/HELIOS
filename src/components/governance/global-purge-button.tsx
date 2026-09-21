"use client";

import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Siren, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { globalPurgeAction } from "@/app/(app)/governance/actions";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogTrigger,
} from "@/components/ui/dialog";

export function GlobalPurgeButton() {
  const [open, setOpen] = React.useState(false);
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () => globalPurgeAction(),
    onSuccess: (count) => {
      toast.error(`Global purge executed — ${count} agent(s) revoked`);
      queryClient.invalidateQueries({ queryKey: ["governance-agents"] });
      setOpen(false);
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="destructive" size="sm">
          <Siren />
          Global purge
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Execute emergency lockdown?</DialogTitle>
          <DialogDescription>
            This revokes every agent identity immediately — trust drops to 0%
            and access level to L0 (isolated) for the entire fleet. This
            cannot be undone from here; agents must be individually restored
            afterward.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            disabled={mutation.isPending}
            onClick={() => mutation.mutate()}
          >
            {mutation.isPending && <Loader2 className="animate-spin" />}
            Execute purge
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
