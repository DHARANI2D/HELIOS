"use client";

import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";

import { getCaseDetailAction } from "@/app/(app)/cases/actions";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { SEVERITY_LABEL, SEVERITY_BADGE_VARIANT } from "@/lib/severity";

interface CaseDetailDialogProps {
  caseId: string | null;
  onClose: () => void;
}

export function CaseDetailDialog({ caseId, onClose }: CaseDetailDialogProps) {
  const { data, isLoading } = useQuery({
    queryKey: ["case-detail", caseId],
    queryFn: () => getCaseDetailAction(caseId!),
    enabled: !!caseId,
  });

  return (
    <Dialog open={!!caseId} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[80vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{data?.title ?? "Case"}</DialogTitle>
          <DialogDescription>{data?.summary}</DialogDescription>
        </DialogHeader>

        {isLoading && (
          <div className="flex justify-center py-10">
            <Loader2 className="animate-spin" />
          </div>
        )}

        {data && (
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={SEVERITY_BADGE_VARIANT[data.severity]}>
                {SEVERITY_LABEL[data.severity]}
              </Badge>
              <Badge variant="outline">{data.status}</Badge>
              {data.riskScore != null && (
                <Badge variant="secondary">Risk {Math.round(data.riskScore)}</Badge>
              )}
            </div>

            <div>
              <p className="mb-2 text-xs font-medium text-muted-foreground">DETECTIONS</p>
              <ul className="space-y-1.5">
                {data.detections.map((d) => (
                  <li key={d.id} className="rounded-md border p-2 text-xs">
                    <span className="font-medium">{d.title}</span>
                    <span className="ml-2 text-muted-foreground">{d.source}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <p className="mb-2 text-xs font-medium text-muted-foreground">TIMELINE</p>
              <ul className="space-y-1.5">
                {data.timeline.map((t) => (
                  <li key={t.id} className="text-xs">
                    <span className="font-medium">{t.action}</span>
                    {t.actor ? ` by ${t.actor}` : ""}
                    {t.detail ? ` — ${t.detail}` : ""}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
