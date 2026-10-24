"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Bot, Loader2, ThumbsDown, ThumbsUp } from "lucide-react";
import { toast } from "sonner";

import { aiFeedbackAction, aiStatusAction, dispatchAgentAction } from "@/app/(app)/cases/actions";
import { Button } from "@/components/ui/button";
import { NativeSelect } from "@/components/ui/native-select";
import { Input } from "@/components/ui/input";

interface AgentOption {
  key: string;
  name: string;
  description: string;
  engine: string;
}

// Pick an agent type and send it onto the case; while it runs the case page
// polls the case's aiStatus and refreshes when the agent is done.
const inFlight = (s: string | null | undefined) => s === "queued" || s === "running";

export function AgentDispatch({ caseId, agents, initialStatus }: { caseId: string; agents: AgentOption[]; initialStatus: string | null }) {
  const router = useRouter();
  const [agent, setAgent] = React.useState(agents[0]?.key ?? "triage");
  const [polling, setPolling] = React.useState(inFlight(initialStatus));
  const refreshedFor = React.useRef<number>(0);

  const { data: status, dataUpdatedAt, refetch } = useQuery({
    queryKey: ["ai-status", caseId],
    queryFn: () => aiStatusAction(caseId),
    enabled: polling,
    refetchInterval: (q) => (q.state.data === undefined || inFlight(q.state.data) ? 2500 : false),
  });

  const dispatch = useMutation({
    mutationFn: () => dispatchAgentAction(caseId, agent),
    onSuccess: () => {
      toast.success("Agent dispatched — results will appear here");
      // Ignore the previous run's final status until the new one is fetched.
      refreshedFor.current = dataUpdatedAt;
      setPolling(true);
      void refetch();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Dispatch failed"),
  });

  // Once the run finishes, re-render the case page with its results.
  React.useEffect(() => {
    if (polling && status && !inFlight(status) && refreshedFor.current !== dataUpdatedAt) {
      refreshedFor.current = dataUpdatedAt;
      router.refresh();
    }
  }, [polling, status, dataUpdatedAt, router]);

  const watching = polling && (status === undefined || inFlight(status));
  const selected = agents.find((a) => a.key === agent);
  const busy = dispatch.isPending || watching;

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-2">
        <NativeSelect value={agent} onChange={(e) => setAgent(e.target.value)} className="min-w-48 flex-1" aria-label="Agent type" disabled={busy}>
          {agents.map((a) => (
            <option key={a.key} value={a.key}>
              {a.name}
            </option>
          ))}
        </NativeSelect>
        <Button onClick={() => dispatch.mutate()} disabled={busy}>
          {busy ? <Loader2 className="animate-spin" /> : <Bot />}
          {watching ? (status === "running" ? "Analyzing…" : "Queued…") : "Dispatch agent"}
        </Button>
      </div>
      {selected && (
        <p className="text-xs text-muted-foreground">
          {selected.description} <span className="text-foreground/70">Runs on {selected.engine}.</span>
        </p>
      )}
    </div>
  );
}

export function AiFeedback({ runId, current }: { runId: string; current: string | null }) {
  const router = useRouter();
  const [note, setNote] = React.useState("");
  const [open, setOpen] = React.useState(false);
  const send = useMutation({
    mutationFn: (feedback: "agree" | "disagree") => aiFeedbackAction(runId, feedback, note),
    onSuccess: () => {
      toast.success("Thanks — feedback recorded against this run");
      setOpen(false);
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Feedback failed"),
  });

  if (current) {
    return (
      <p className="text-xs text-muted-foreground">
        Analyst {current === "agree" ? "agreed with" : "disagreed with"} this analysis.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">Is this analysis right?</span>
        <Button size="sm" variant="outline" className="h-7" onClick={() => send.mutate("agree")} disabled={send.isPending}>
          <ThumbsUp /> Agree
        </Button>
        <Button size="sm" variant="outline" className="h-7" onClick={() => (open ? send.mutate("disagree") : setOpen(true))} disabled={send.isPending}>
          <ThumbsDown /> {open ? "Send" : "Disagree"}
        </Button>
      </div>
      {open && <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="What did it get wrong? (helps tune the agent)" className="h-8 text-xs" />}
    </div>
  );
}
