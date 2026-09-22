"use client";

import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Play, Loader2, Radio } from "lucide-react";
import { toast } from "sonner";

import { runSimulationAction } from "@/app/(app)/cases/actions";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export function SimulatePanel() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (count: number) => runSimulationAction(count),
    onSuccess: (result) => {
      toast.success(
        `Ran ${result.scenariosRun.length} scenarios → ${result.detectionCount} detection(s), ${result.caseIds.length} case(s) created`,
      );
      queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
    onError: () => toast.error("Simulation failed"),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Attack simulation</CardTitle>
        <CardDescription>
          Ingests synthetic logs across MITRE tactics and runs all 11
          detectors against them
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap items-center gap-2">
        {[3, 6, 12].map((count) => (
          <Button
            key={count}
            variant="outline"
            disabled={mutation.isPending}
            onClick={() => mutation.mutate(count)}
          >
            {mutation.isPending ? <Loader2 className="animate-spin" /> : <Play />}
            Run {count} scenarios
          </Button>
        ))}
        {mutation.isPending && (
          <span className="flex items-center gap-1 text-xs text-muted-foreground">
            <Radio className="size-3 animate-pulse" /> simulating…
          </span>
        )}
      </CardContent>
    </Card>
  );
}
