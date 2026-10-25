"use client";

import { CircleCheck, CircleDashed, X } from "lucide-react";

import { capabilityName, capabilityShort } from "@/lib/assets/capabilities";
import type { SurfaceCoverage } from "@/lib/assets/coverage";
import type { Priority } from "@/lib/assets/surface";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export const PRIORITY_VARIANT: Record<Priority, "destructive" | "warning" | "soft"> = { P1: "destructive", P2: "warning", P3: "soft" };

export function PriorityBadge({ priority }: { priority: Priority }) {
  return <Badge variant={PRIORITY_VARIANT[priority]} className="font-mono text-[10px]">{priority}</Badge>;
}

// Coverage of each asset group the client has: required capabilities
// covered, and the gaps.
export function SurfaceCoverageCard({ coverage, audience }: { coverage: SurfaceCoverage; audience: "staff" | "public" }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center justify-between text-sm">
          Attack-surface coverage
          {coverage.classes.length > 0 && <span className="text-base font-semibold tabular">{coverage.score}%</span>}
        </CardTitle>
        {coverage.classes.length > 0 && (
          <div className="h-1.5 overflow-hidden rounded-full bg-muted" role="img" aria-label={`${coverage.score}% of required capabilities covered, weighted by priority`}>
            <div className={cn("h-full rounded-full", coverage.score >= 90 ? "bg-success" : coverage.score >= 60 ? "bg-warning" : "bg-destructive")} style={{ width: `${coverage.score}%` }} />
          </div>
        )}
        <CardDescription className="text-[11px]">Required capabilities per asset group, weighted P1 3×, P2 2×, P3 1×.</CardDescription>
      </CardHeader>
      <CardContent>
        {coverage.classes.length === 0 ? (
          <p className="text-xs text-muted-foreground">Enter {audience === "public" ? "your" : "the client's"} devices, users and the rest of the estate to see coverage.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {coverage.classes.map((c) => {
              const covered = c.required.filter((r) => r.by.length).length;
              return (
                <li key={c.info.key} className="text-xs">
                  <div className="flex items-center gap-1.5">
                    {c.gaps.length === 0 ? <CircleCheck className="size-3.5 shrink-0 text-success-ink" /> : c.priority === "P1" ? <X className="size-3.5 shrink-0 text-destructive" /> : <CircleDashed className="size-3.5 shrink-0 text-warning-ink" />}
                    <span className="font-medium">{c.info.label}</span>
                    <PriorityBadge priority={c.priority} />
                    <span className="ml-auto tabular text-muted-foreground">{covered}/{c.required.length}</span>
                  </div>
                  {c.gaps.length > 0 && (
                    <p className="mt-0.5 flex flex-wrap gap-1 pl-5">
                      {c.gaps.map((g) => <Badge key={g} variant="outline" className="font-mono text-[10px] text-destructive" title={`Missing: ${capabilityName(g)}`}>{capabilityShort(g)}</Badge>)}
                    </p>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
