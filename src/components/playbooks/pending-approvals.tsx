"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, X, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { listPendingApprovalsAction, decideApprovalAction } from "@/app/(app)/playbooks/actions";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SEVERITY_LABEL, SEVERITY_BADGE_VARIANT } from "@/lib/severity";

export function PendingApprovals() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["pending-approvals"],
    queryFn: () => listPendingApprovalsAction(),
    refetchInterval: 10000,
  });

  const decide = useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: "approved" | "rejected" }) =>
      decideApprovalAction(id, decision),
    onSuccess: (_, { decision }) => {
      toast.success(decision === "approved" ? "Playbook approved and executed" : "Playbook rejected");
      queryClient.invalidateQueries({ queryKey: ["pending-approvals"] });
      queryClient.invalidateQueries({ queryKey: ["executions"] });
    },
  });

  if (!isLoading && !data?.length) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Pending approvals</CardTitle>
        <CardDescription>Playbooks awaiting human sign-off before executing</CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex justify-center py-6">
            <Loader2 className="animate-spin" />
          </div>
        ) : (
          <ul className="space-y-2">
            {data?.map((exec) => (
              <li key={exec.id} className="flex items-center justify-between gap-2 rounded-md border p-2.5">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{exec.playbook.name}</p>
                  <p className="truncate text-xs text-muted-foreground">{exec.case.title}</p>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <Badge variant={SEVERITY_BADGE_VARIANT[exec.case.severity]}>
                    {SEVERITY_LABEL[exec.case.severity]}
                  </Badge>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={decide.isPending}
                    onClick={() => decide.mutate({ id: exec.id, decision: "rejected" })}
                  >
                    <X />
                  </Button>
                  <Button
                    size="sm"
                    disabled={decide.isPending}
                    onClick={() => decide.mutate({ id: exec.id, decision: "approved" })}
                  >
                    <Check />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
