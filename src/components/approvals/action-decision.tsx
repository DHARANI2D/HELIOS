"use client";

import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Check, Loader2, X } from "lucide-react";
import { toast } from "sonner";

import { decideResponseActionAction } from "@/app/(app)/cases/actions";
import { Button } from "@/components/ui/button";
import { unwrap } from "@/lib/action-result";

// Approve or reject one held response action from the inbox. The response
// policy still decides (two-person rule, client rulebook) when it's approved.
export function ActionDecision({ actionId }: { actionId: string }) {
  const router = useRouter();
  const decide = useMutation({
    mutationFn: (decision: "approved" | "rejected") => unwrap(decideResponseActionAction(actionId, decision)),
    onSuccess: ({ status }, decision) => {
      toast.success(decision === "rejected" ? "Rejected" : status === "PENDING_APPROVAL" ? "Approved; it needs one more approver" : `Approved: ${status.toLowerCase().replaceAll("_", " ")}`);
      router.refresh();
    },
    onError: (err: Error) => toast.error(err.message),
  });
  return (
    <div className="flex gap-1.5">
      <Button size="sm" onClick={() => decide.mutate("approved")} disabled={decide.isPending}>
        {decide.isPending && decide.variables === "approved" ? <Loader2 className="animate-spin" /> : <Check />} Approve
      </Button>
      <Button size="sm" variant="outline" onClick={() => decide.mutate("rejected")} disabled={decide.isPending}>
        {decide.isPending && decide.variables === "rejected" ? <Loader2 className="animate-spin" /> : <X />} Reject
      </Button>
    </div>
  );
}
