"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery } from "@tanstack/react-query";
import { CheckCheck, Eye, Loader2, RefreshCw } from "lucide-react";
import { toast } from "sonner";

import { analysisStatusAction, reanalyseCaseAction, reviewFinalAnalysisAction } from "@/app/(app)/cases/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { unwrap } from "@/lib/action-result";

// The SOC marks a final analysis reviewed (with an optional note).
export function ReviewFinalAnalysis({ reportId }: { reportId: string }) {
  const router = useRouter();
  const [note, setNote] = React.useState("");
  const review = useMutation({
    mutationFn: () => unwrap(reviewFinalAnalysisAction(reportId, note)),
    onSuccess: () => {
      toast.success("Final analysis marked reviewed");
      router.refresh();
    },
    onError: (err: Error) => toast.error(err.message),
  });
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Review note (optional)" className="h-8 min-w-48 flex-1 text-xs" maxLength={2000} />
      <Button size="sm" onClick={() => review.mutate()} disabled={review.isPending}>
        {review.isPending ? <Loader2 className="animate-spin" /> : <CheckCheck />} Mark reviewed
      </Button>
    </div>
  );
}

// The client says they've read it.
export function AcknowledgeFinalAnalysis({ reportId }: { reportId: string }) {
  const router = useRouter();
  const ack = useMutation({
    mutationFn: () => unwrap(reviewFinalAnalysisAction(reportId)),
    onSuccess: () => {
      toast.success("Acknowledged");
      router.refresh();
    },
    onError: (err: Error) => toast.error(err.message),
  });
  return (
    <Button size="sm" variant="outline" onClick={() => ack.mutate()} disabled={ack.isPending}>
      {ack.isPending ? <Loader2 className="animate-spin" /> : <Eye />} Acknowledge
    </Button>
  );
}

// Ask HELIOS to analyse the case again; the panel refreshes when it's done.
export function ReanalyseCase({ caseId, initialStatus }: { caseId: string; initialStatus: string | null }) {
  const router = useRouter();
  const [polling, setPolling] = React.useState(initialStatus === "running");
  const refreshedFor = React.useRef<number>(0);
  const { data: status, dataUpdatedAt, refetch } = useQuery({
    queryKey: ["analysis-status", caseId],
    queryFn: () => unwrap(analysisStatusAction(caseId)),
    enabled: polling,
    refetchInterval: (q) => (q.state.data === undefined || q.state.data === "running" ? 4000 : false),
  });
  // Once the run finishes, re-render the case page with the new analysis.
  React.useEffect(() => {
    if (polling && status && status !== "running" && refreshedFor.current !== dataUpdatedAt) {
      refreshedFor.current = dataUpdatedAt;
      router.refresh();
    }
  }, [polling, status, dataUpdatedAt, router]);
  const run = useMutation({
    mutationFn: () => unwrap(reanalyseCaseAction(caseId)),
    onSuccess: () => {
      toast.success("HELIOS is analysing the case again");
      // Ignore the previous run's final status until the new one is fetched.
      refreshedFor.current = dataUpdatedAt;
      setPolling(true);
      void refetch();
    },
    onError: (err: Error) => toast.error(err.message),
  });
  const busy = run.isPending || (polling && (status === undefined || status === "running"));
  return (
    <Button size="sm" variant="outline" onClick={() => run.mutate()} disabled={busy}>
      {busy ? <Loader2 className="animate-spin" /> : <RefreshCw />} {busy ? "Analysing…" : "Analyse again"}
    </Button>
  );
}
