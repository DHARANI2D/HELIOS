"use client";

import { useQuery } from "@tanstack/react-query";
import { Loader2, CheckCircle2, XCircle } from "lucide-react";

import { getInvestigationAction } from "@/app/(app)/investigations/actions";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { SEVERITY_LABEL, SEVERITY_BADGE_VARIANT } from "@/lib/severity";
import { EntityGraphView } from "@/components/investigations/entity-graph-view";
import type { EntityGraph, QaResult, TriageResult } from "@/lib/investigations/types";

interface Props {
  caseId: string | null;
  onClose: () => void;
}

export function InvestigationDetailDialog({ caseId, onClose }: Props) {
  const { data, isLoading } = useQuery({
    queryKey: ["investigation-detail", caseId],
    queryFn: () => getInvestigationAction(caseId!),
    enabled: !!caseId,
  });

  const metadata = data?.metadata as
    | { triage?: TriageResult; qa?: QaResult; graphData?: EntityGraph; finalReport?: string }
    | undefined;

  return (
    <Dialog open={!!caseId} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{data?.title ?? "Investigation"}</DialogTitle>
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
              {data.confidence != null && (
                <Badge variant="secondary">Confidence {Math.round(data.confidence * 100)}%</Badge>
              )}
              {metadata?.qa && (
                <Badge
                  variant={metadata.qa.is_valid ? "secondary" : "destructive"}
                  className="gap-1"
                >
                  {metadata.qa.is_valid ? (
                    <CheckCircle2 className="size-3" />
                  ) : (
                    <XCircle className="size-3" />
                  )}
                  QA {metadata.qa.is_valid ? "validated" : "unresolved"}
                </Badge>
              )}
            </div>

            <Tabs defaultValue="rca">
              <TabsList>
                <TabsTrigger value="rca">Root Cause</TabsTrigger>
                <TabsTrigger value="graph">Entity Graph</TabsTrigger>
                <TabsTrigger value="qa">QA</TabsTrigger>
                <TabsTrigger value="report">Report</TabsTrigger>
              </TabsList>

              <TabsContent value="rca" className="flex flex-col gap-3">
                <p className="text-sm">{data.rootCauseNarrative}</p>
                <div>
                  <p className="mb-2 text-xs font-medium text-muted-foreground">TIMELINE</p>
                  <ul className="space-y-1.5">
                    {data.timeline.map((t) => (
                      <li key={t.id} className="text-xs">
                        {t.detail}
                      </li>
                    ))}
                  </ul>
                </div>
              </TabsContent>

              <TabsContent value="graph">
                {metadata?.graphData && <EntityGraphView graph={metadata.graphData} />}
              </TabsContent>

              <TabsContent value="qa" className="flex flex-col gap-3">
                {metadata?.qa && (
                  <>
                    <div>
                      <p className="mb-2 text-xs font-medium text-muted-foreground">
                        VALIDATED EVIDENCE
                      </p>
                      <ul className="list-inside list-disc space-y-1 text-xs">
                        {metadata.qa.validated_evidence.map((e, i) => (
                          <li key={i}>{e}</li>
                        ))}
                      </ul>
                    </div>
                    {metadata.qa.issues.length > 0 && (
                      <div>
                        <p className="mb-2 text-xs font-medium text-destructive">ISSUES</p>
                        <ul className="list-inside list-disc space-y-1 text-xs text-destructive">
                          {metadata.qa.issues.map((e, i) => (
                            <li key={i}>{e}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </>
                )}
              </TabsContent>

              <TabsContent value="report">
                <pre className="whitespace-pre-wrap text-xs">{metadata?.finalReport}</pre>
              </TabsContent>
            </Tabs>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
