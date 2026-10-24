"use client";

import * as React from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { KeyRound, ShieldCheck, ShieldX, ShieldAlert, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { listAgentsAction, rotateAgentTokenAction } from "@/app/(app)/governance/actions";
import { Button } from "@/components/ui/button";
import { AgentTokenDialog } from "@/components/governance/identity-form";
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

export function AgentGrid({ origin }: { origin: string }) {
  const [investigatingId, setInvestigatingId] = React.useState<string | null>(null);
  const [issued, setIssued] = React.useState<{ name: string; token: string } | null>(null);
  const rotate = useMutation({
    mutationFn: (id: string) => rotateAgentTokenAction(id),
    onSuccess: (r) => setIssued({ name: r.name, token: r.token }),
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });

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
        No governed agents yet. Issue an identity for each AI agent that acts on a client&apos;s systems.
      </p>
    );
  }

  return (
    <>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
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
                <div className="flex items-end justify-between gap-2">
                  <p className="min-w-0 text-xs text-muted-foreground">
                    <span className="block truncate">{agent.tenant?.name ?? "SOC-wide"}</span>
                    <span className="block">L{agent.level} · {agent.mode?.toLowerCase().replace("_", " ") ?? "—"}</span>
                    {agent.tokenPrefix && <span className="block font-mono text-[10px]">{agent.tokenPrefix}</span>}
                  </p>
                  {agent.status !== "REVOKED" && (
                    <Button size="sm" variant="ghost" className="h-7" disabled={rotate.isPending} title="Issue a new API token; the old one stops working" onClick={(e) => { e.stopPropagation(); rotate.mutate(agent.id); }}>
                      <KeyRound /> Token
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <AgentTokenDialog issued={issued} origin={origin} onClose={() => setIssued(null)} />
      <InvestigationDialog
        agentId={investigatingId}
        onClose={() => setInvestigatingId(null)}
      />
    </>
  );
}
