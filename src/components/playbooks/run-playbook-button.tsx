"use client";

import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Play } from "lucide-react";
import { toast } from "sonner";

import { runPlaybookOnCaseAction } from "@/app/(app)/cases/actions";
import { Button } from "@/components/ui/button";

export function RunPlaybookButton({ caseId, playbookId }: { caseId: string; playbookId: string }) {
  const router = useRouter();
  const run = useMutation({
    mutationFn: () => runPlaybookOnCaseAction(caseId, playbookId),
    onSuccess: ({ queued }) => {
      toast.success(queued ? "Queued for approval" : "Playbook executed");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Run failed"),
  });
  return (
    <Button size="sm" variant="outline" onClick={() => run.mutate()} disabled={run.isPending}>
      {run.isPending ? <Loader2 className="animate-spin" /> : <Play />}
      Run
    </Button>
  );
}
