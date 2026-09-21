"use client";

import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";

import {
  investigateAgentAction,
  restoreAgentAction,
  confirmBreachAction,
} from "@/app/(app)/governance/actions";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SEVERITY_LABEL, SEVERITY_BADGE_VARIANT } from "@/lib/severity";

interface InvestigationDialogProps {
  agentId: string | null;
  onClose: () => void;
}

export function InvestigationDialog({ agentId, onClose }: InvestigationDialogProps) {
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["governance-investigation", agentId],
    queryFn: () => investigateAgentAction(agentId!),
    enabled: !!agentId,
  });

  function invalidate() {
    queryClient.invalidateQueries({ queryKey: ["governance-agents"] });
    queryClient.invalidateQueries({ queryKey: ["governance-investigation"] });
  }

  const restore = useMutation({
    mutationFn: () => restoreAgentAction(agentId!, "Reviewed by analyst — false positive"),
    onSuccess: () => {
      toast.success("Agent restored");
      invalidate();
      onClose();
    },
  });

  const confirm = useMutation({
    mutationFn: () => confirmBreachAction(agentId!, "Confirmed via investigation dialog"),
    onSuccess: () => {
      toast.success("Breach confirmed");
      invalidate();
      onClose();
    },
  });

  return (
    <Dialog open={!!agentId} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[80vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Breach investigation</DialogTitle>
          <DialogDescription>{data?.agent.name}</DialogDescription>
        </DialogHeader>

        {isLoading && (
          <div className="flex justify-center py-10">
            <Loader2 className="animate-spin" />
          </div>
        )}

        {data && data.case && (
          <div className="flex flex-col gap-4">
            <div className="flex items-center gap-2">
              <Badge variant={SEVERITY_BADGE_VARIANT[data.case.severity]}>
                {SEVERITY_LABEL[data.case.severity]}
              </Badge>
              <span className="text-sm text-muted-foreground">{data.case.title}</span>
            </div>

            {data.case.rootCauseNarrative && (
              <p className="text-sm">{data.case.rootCauseNarrative}</p>
            )}

            <div>
              <p className="mb-2 text-xs font-medium text-muted-foreground">
                DETECTIONS
              </p>
              <ul className="space-y-1.5">
                {data.case.detections.map((d) => (
                  <li key={d.id} className="rounded-md border p-2 text-xs">
                    <span className="font-medium">{d.title}</span>
                    <span className="ml-2 text-muted-foreground">{d.source}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <p className="mb-2 text-xs font-medium text-muted-foreground">
                TIMELINE
              </p>
              <ul className="space-y-1.5">
                {data.case.timeline.map((t) => (
                  <li key={t.id} className="text-xs">
                    <span className="font-medium">{t.action}</span>
                    {t.detail ? ` — ${t.detail}` : ""}
                  </li>
                ))}
              </ul>
            </div>

            {data.recommendation && (
              <p className="rounded-md bg-muted p-3 text-xs">{data.recommendation}</p>
            )}
          </div>
        )}

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => confirm.mutate()}
            disabled={confirm.isPending || restore.isPending}
          >
            {confirm.isPending && <Loader2 className="animate-spin" />}
            Confirm breach
          </Button>
          <Button
            onClick={() => restore.mutate()}
            disabled={confirm.isPending || restore.isPending}
          >
            {restore.isPending && <Loader2 className="animate-spin" />}
            Restore agent
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
