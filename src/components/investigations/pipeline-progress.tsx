"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { CheckCircle2, Circle, Loader2, RotateCcw, XCircle } from "lucide-react";
import { toast } from "sonner";

import { rerunInvestigationAction } from "@/app/(app)/investigations/actions";
import { Button } from "@/components/ui/button";
import type { InvestigationMetadata } from "@/lib/investigations/service";

const STAGE_LABEL = { triage: "Triage", rca: "Root cause analysis", qa: "Adversarial QA", report: "Report" } as const;
const STALL_MS = 15 * 60 * 1000;

export function PipelineProgress({ caseId, pipeline }: { caseId: string; pipeline: InvestigationMetadata["pipeline"] }) {
  const router = useRouter();
  const active = pipeline.status === "queued" || pipeline.status === "running";
  const [now, setNow] = React.useState(() => Date.now());

  // Poll while the background pipeline runs; server components re-render
  // with the latest metadata on each refresh.
  React.useEffect(() => {
    if (!active) return;
    const id = setInterval(() => {
      setNow(Date.now());
      router.refresh();
    }, 2500);
    return () => clearInterval(id);
  }, [active, router]);

  const stalled = active && now - Date.parse(pipeline.startedAt) > STALL_MS;

  const rerun = useMutation({
    mutationFn: () => rerunInvestigationAction(caseId),
    onSuccess: () => {
      toast.success("Investigation re-queued");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Re-run failed"),
  });

  return (
    <div className="flex flex-col gap-3">
      <ol className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {pipeline.stages.map((s) => (
          <li key={s.name} className="flex items-start gap-2 rounded-md border p-2.5 text-sm">
            {s.status === "done" ? (
              <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" />
            ) : s.status === "running" ? (
              <Loader2 className="mt-0.5 size-4 shrink-0 animate-spin" />
            ) : s.status === "failed" ? (
              <XCircle className="mt-0.5 size-4 shrink-0 text-destructive" />
            ) : (
              <Circle className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
            )}
            <div className="min-w-0">
              <p className="font-medium">{STAGE_LABEL[s.name]}</p>
              <p className="text-xs text-muted-foreground">
                {s.status}
                {s.engine && ` · ${s.engine === "claude" ? "Claude" : "deterministic"}`}
                {s.name === "qa" && pipeline.qaIterations > 1 && ` · ${pipeline.qaIterations} rounds`}
              </p>
              {s.note && <p className="mt-1 text-xs text-warning-foreground">{s.note}</p>}
            </div>
          </li>
        ))}
      </ol>
      {pipeline.status === "failed" && <p className="text-sm text-destructive">Pipeline failed: {pipeline.error}</p>}
      {(pipeline.status === "failed" || pipeline.status === "completed" || stalled) && (
        <div className="flex items-center gap-3">
          <Button size="sm" variant="outline" onClick={() => rerun.mutate()} disabled={rerun.isPending}>
            {rerun.isPending ? <Loader2 className="animate-spin" /> : <RotateCcw />}
            Re-run pipeline
          </Button>
          {stalled && <span className="text-xs text-muted-foreground">No progress for 15+ minutes — the server may have restarted mid-run.</span>}
        </div>
      )}
    </div>
  );
}
