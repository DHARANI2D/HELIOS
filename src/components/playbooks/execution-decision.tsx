"use client";

import { useRouter } from "next/navigation";
import { useSession } from "next-auth/react";
import { useMutation } from "@tanstack/react-query";
import { Check, Loader2, X } from "lucide-react";
import { toast } from "sonner";

import { decideExecutionAction } from "@/app/(app)/playbooks/actions";
import { Button } from "@/components/ui/button";

export function ExecutionDecision({ executionId }: { executionId: string }) {
  const router = useRouter();
  const { data: session } = useSession();
  const isAdmin = session?.user?.role === "ADMIN";

  const decide = useMutation({
    mutationFn: (decision: "approved" | "rejected") => decideExecutionAction(executionId, decision),
    onSuccess: ({ status }) => {
      toast.success(status === "REJECTED" ? "Execution rejected" : `Playbook ${status === "SUCCEEDED" ? "executed" : status.toLowerCase()}`);
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Decision failed"),
  });

  if (!isAdmin) {
    return <span className="text-xs text-muted-foreground">Awaiting admin approval</span>;
  }

  return (
    <div className="flex gap-1.5">
      <Button size="sm" onClick={() => decide.mutate("approved")} disabled={decide.isPending}>
        {decide.isPending && decide.variables === "approved" ? <Loader2 className="animate-spin" /> : <Check />}
        Approve
      </Button>
      <Button size="sm" variant="outline" onClick={() => decide.mutate("rejected")} disabled={decide.isPending}>
        {decide.isPending && decide.variables === "rejected" ? <Loader2 className="animate-spin" /> : <X />}
        Reject
      </Button>
    </div>
  );
}
