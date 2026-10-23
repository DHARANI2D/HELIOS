"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Loader2, Swords } from "lucide-react";
import { toast } from "sonner";

import { listTacticsAction, runSimulationAction } from "@/app/(app)/cases/actions";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { cn } from "@/lib/utils";

export function SimulationPanel() {
  const router = useRouter();
  const [tactics, setTactics] = React.useState<string[]>([]);
  const [count, setCount] = React.useState(10);
  const [intensity, setIntensity] = React.useState<"low" | "medium" | "high">("medium");

  const { data: available } = useQuery({ queryKey: ["siem-tactics"], queryFn: () => listTacticsAction() });

  const run = useMutation({
    mutationFn: () => runSimulationAction(tactics.length ? { tactics } : { count, intensity }),
    onSuccess: ({ scenarios, summary }) => {
      toast.success(
        `Replayed ${scenarios.length} scenarios: ${summary.eventsIngested} events → ${summary.newDetections} detections, ` +
          `${summary.casesCreated} new / ${summary.casesUpdated} updated cases`,
      );
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Simulation failed"),
  });

  const toggle = (t: string) => setTactics((cur) => (cur.includes(t) ? cur.filter((x) => x !== t) : [...cur, t]));

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Attack simulation</CardTitle>
        <CardDescription>
          Replay signal-fusion&apos;s 48 ATT&amp;CK scenarios through the live ingestion and detection pipeline.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-wrap gap-1.5">
          {available?.map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => toggle(t)}
              className={cn(
                "rounded-md border px-2 py-0.5 text-xs transition-colors hover:bg-accent",
                tactics.includes(t) && "border-primary bg-primary text-primary-foreground hover:bg-primary/90",
              )}
            >
              {t}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="sim-count" className="text-xs">Random scenarios</Label>
            <Input
              id="sim-count"
              type="number"
              min={1}
              max={48}
              value={count}
              disabled={tactics.length > 0}
              onChange={(e) => setCount(Math.max(1, Math.min(48, Number(e.target.value) || 1)))}
              className="w-24"
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="sim-intensity" className="text-xs">Intensity</Label>
            <NativeSelect
              id="sim-intensity"
              value={intensity}
              disabled={tactics.length > 0}
              onChange={(e) => setIntensity(e.target.value as typeof intensity)}
            >
              <option value="low">Low / medium only</option>
              <option value="medium">Any</option>
              <option value="high">High only</option>
            </NativeSelect>
          </div>
          <Button onClick={() => run.mutate()} disabled={run.isPending}>
            {run.isPending ? <Loader2 className="animate-spin" /> : <Swords />}
            {tactics.length ? `Run ${tactics.length} tactic${tactics.length > 1 ? "s" : ""}` : "Run simulation"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
