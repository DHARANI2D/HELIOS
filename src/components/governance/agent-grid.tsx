"use client";

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldCheck, ShieldX, ShieldAlert, Loader2 } from "lucide-react";

import { listAgentsAction } from "@/app/(app)/governance/actions";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { InvestigationDialog } from "@/components/governance/investigation-dialog";
import { cn } from "@/lib/utils";

const STATUS_STYLE: Record<string, { icon: typeof ShieldCheck; badge: "secondary" | "destructive" | "outline" }> = {
  ACTIVE: { icon: ShieldCheck, badge: "secondary" },
  ISOLATED: { icon: ShieldAlert, badge: "outline" },
  REVOKED: { icon: ShieldX, badge: "destructive" },
};

export function AgentGrid() {
  const [investigatingId, setInvestigatingId] = React.useState<string | null>(null);

  const { data: agents, isLoading } = useQuery({
    queryKey: ["governance-agents"],
    queryFn: () => listAgentsAction(),
    refetchInterval: 5000,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 className="animate-spin" />
      </div>
    );
  }

  if (!agents?.length) {
    return (
      <p className="py-10 text-center text-sm text-muted-foreground">
        No agents yet. Issue an identity or run a scenario below.
      </p>
    );
  }

  return (
    <>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {agents.map((agent) => {
          const style = STATUS_STYLE[agent.status] ?? STATUS_STYLE.ACTIVE;
          const Icon = style.icon;
          return (
            <Card
              key={agent.id}
              className={cn(
                agent.status === "REVOKED" && "cursor-pointer hover:border-destructive/60",
              )}
              onClick={() => {
                if (agent.status === "REVOKED") setInvestigatingId(agent.id);
              }}
            >
              <CardContent className="flex flex-col gap-3">
                <div className="flex items-center justify-between">
                  <span className="truncate text-sm font-medium">{agent.name}</span>
                  <Badge variant={style.badge} className="gap-1">
                    <Icon className="size-3" />
                    {agent.status}
                  </Badge>
                </div>
                <div>
                  <div className="mb-1 flex items-center justify-between text-xs text-muted-foreground">
                    <span>Trust</span>
                    <span className="tabular-nums">{Math.round(agent.trust)}%</span>
                  </div>
                  <Progress value={agent.trust} />
                </div>
                <p className="text-xs text-muted-foreground">
                  Level L{agent.level} · {agent.mode ?? "—"}
                </p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <InvestigationDialog
        agentId={investigatingId}
        onClose={() => setInvestigatingId(null)}
      />
    </>
  );
}
