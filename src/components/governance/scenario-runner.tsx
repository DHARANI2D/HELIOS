"use client";

import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Play, Loader2, TriangleAlert } from "lucide-react";
import { toast } from "sonner";

import {
  listScenariosAction,
  runScenarioAction,
} from "@/app/(app)/governance/actions";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { GlobalPurgeButton } from "@/components/governance/global-purge-button";
import type { RunScenarioResult } from "@/lib/governance/simulator";

export function ScenarioRunner() {
  const queryClient = useQueryClient();
  const [lastRun, setLastRun] = React.useState<RunScenarioResult | null>(null);
  const [runningId, setRunningId] = React.useState<string | null>(null);

  const { data: scenarios } = useQuery({
    queryKey: ["governance-scenarios"],
    queryFn: () => listScenariosAction(),
  });

  const mutation = useMutation({
    mutationFn: (id: string) => runScenarioAction(id),
    onMutate: (id) => setRunningId(id),
    onSuccess: (result) => {
      setLastRun(result);
      if (result.revoked) {
        toast.error("Agent revoked — breach contained");
      } else {
        toast.success("Scenario completed");
      }
      queryClient.invalidateQueries({ queryKey: ["governance-agents"] });
    },
    onSettled: () => setRunningId(null),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div>
          <CardTitle className="text-base">Security scenarios</CardTitle>
          <CardDescription>
            Simulate an attack and watch the governance pipeline respond
          </CardDescription>
        </div>
        <GlobalPurgeButton />
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {scenarios?.map((s) => (
            <div
              key={s.id}
              className="flex items-center justify-between gap-2 rounded-md border p-2.5"
            >
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">{s.name}</p>
                <p className="truncate text-xs text-muted-foreground">
                  {s.description}
                </p>
              </div>
              <Button
                size="sm"
                variant="outline"
                disabled={runningId === s.id}
                onClick={() => mutation.mutate(s.id)}
              >
                {runningId === s.id ? (
                  <Loader2 className="animate-spin" />
                ) : (
                  <Play />
                )}
                Run
              </Button>
            </div>
          ))}
        </div>

        {lastRun && (
          <div className="rounded-md border bg-muted/40 p-3">
            <div className="mb-2 flex items-center gap-2 text-xs font-medium">
              <TriangleAlert className="size-3.5" />
              Pipeline output for agent {lastRun.agentId}
              {lastRun.revoked && <Badge variant="destructive">REVOKED</Badge>}
            </div>
            <ul className="space-y-1">
              {lastRun.steps.map((step, i) => (
                <li key={i} className="text-xs">
                  <span className="font-medium">{step.eventName}</span>
                  {" → "}
                  <Badge
                    variant={step.decision === "ALLOW" ? "secondary" : "destructive"}
                    className="mx-1"
                  >
                    {step.decision}
                  </Badge>
                  <span className="text-muted-foreground">
                    [{step.layer}] {step.reason}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
