"use client";

import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { UserPlus, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { issueIdentityAction } from "@/app/(app)/governance/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function IdentityForm() {
  const [name, setName] = React.useState("");
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (agentName: string) => issueIdentityAction(agentName),
    onSuccess: (agent) => {
      toast.success(`Issued identity for ${agent.name}`);
      setName("");
      queryClient.invalidateQueries({ queryKey: ["governance-agents"] });
    },
    onError: () => toast.error("Failed to issue identity"),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Issue agent identity</CardTitle>
      </CardHeader>
      <CardContent>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (name.trim().length < 3) {
              toast.error("Agent name must be at least 3 characters");
              return;
            }
            mutation.mutate(name.trim());
          }}
          className="flex gap-2"
        >
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. billing-agent"
          />
          <Button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? (
              <Loader2 className="animate-spin" />
            ) : (
              <UserPlus />
            )}
            Issue
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
