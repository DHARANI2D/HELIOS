"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";

import { listPlaybooksAction, togglePlaybookAction } from "@/app/(app)/playbooks/actions";
import { Card, CardContent } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";

export function PlaybookList() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["playbooks"],
    queryFn: () => listPlaybooksAction(),
  });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => togglePlaybookAction(id, enabled),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["playbooks"] }),
  });

  if (isLoading) {
    return (
      <div className="flex justify-center py-10 text-muted-foreground">
        <Loader2 className="animate-spin" />
      </div>
    );
  }

  if (!data?.length) {
    return (
      <p className="py-10 text-center text-sm text-muted-foreground">
        No playbooks yet — create one above.
      </p>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      {data.map((pb) => (
        <Card key={pb.id}>
          <CardContent className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium">{pb.name}</p>
              <Switch
                checked={pb.enabled}
                onCheckedChange={(checked) => toggle.mutate({ id: pb.id, enabled: checked })}
              />
            </div>
            <p className="text-xs text-muted-foreground">{pb.description}</p>
            <div className="flex flex-wrap gap-1">
              {pb.actions.map((a) => (
                <Badge key={a.id} variant="outline" className="text-[10px]">
                  {a.actionType.replaceAll("_", " ")}
                </Badge>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">
              {pb._count.executions} execution(s) · {pb.autoExecute ? "auto" : "manual"} ·{" "}
              {pb.requireApproval ? "needs approval" : "no approval"}
            </p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
