"use client";

import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { UserPlus, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { issueIdentityAction } from "@/app/(app)/governance/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { CopyField } from "@/components/integrations/onboard-wizard";
import { unwrap } from "@/lib/action-result";

export function AgentTokenDialog({ issued, origin, onClose }: { issued: { name: string; token: string } | null; origin: string; onClose: () => void }) {
  return (
    <Dialog open={!!issued} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>API token for {issued?.name}</DialogTitle>
          <DialogDescription>Shown once — store it in the agent&apos;s secret store. The agent asks this endpoint before every action and proceeds only on ALLOW.</DialogDescription>
        </DialogHeader>
        {issued && (
          <div className="grid gap-3 text-sm">
            <CopyField label="Endpoint (POST)" value={`${origin}/api/governance/evaluate`} />
            <CopyField label="Authorization: Bearer" value={issued.token} />
            <div className="rounded-md bg-muted p-3 text-xs">
              <p className="font-medium">Request body (JSON)</p>
              <ul className="mt-1 list-disc space-y-0.5 pl-4 text-muted-foreground">
                <li><code>action.name</code> — the intent, e.g. one from your policy taxonomy</li>
                <li><code>action.target</code> — what it acts on (optional)</li>
                <li><code>action.reasoning</code> — the agent&apos;s reasoning steps (optional, checked for goal drift)</li>
                <li><code>action.confidence</code> — 0–1 (optional)</li>
                <li><code>environment</code> — production, staging or development</li>
              </ul>
              <p className="mt-2 text-muted-foreground">Response: <code>decision</code> (ALLOW / DENY / ESCALATE), <code>layer</code>, <code>reason</code>, <code>trust</code>, <code>caseId</code>.</p>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

export function IdentityForm({ origin }: { origin: string }) {
  const [name, setName] = React.useState("");
  const [issued, setIssued] = React.useState<{ name: string; token: string } | null>(null);
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (agentName: string) => unwrap(issueIdentityAction(agentName)),
    onSuccess: (agent) => {
      setIssued({ name: agent.name, token: agent.token });
      setName("");
      queryClient.invalidateQueries({ queryKey: ["governance-agents"] });
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to issue identity"),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Govern an AI agent</CardTitle>
        <CardDescription>Issue an identity and API token for an AI agent that runs on a client&apos;s estate. Its actions are checked against the constitution, reasoning, DLP and policy before they happen.</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate(name.trim());
          }}
          className="grid gap-2"
        >
          <Label htmlFor="agent-name" className="text-xs">Agent name</Label>
          <div className="flex gap-2">
            <Input id="agent-name" value={name} onChange={(e) => setName(e.target.value)} aria-describedby="agent-name-hint" />
            <Button type="submit" disabled={mutation.isPending || name.trim().length < 3}>
              {mutation.isPending ? <Loader2 className="animate-spin" /> : <UserPlus />}
              Issue
            </Button>
          </div>
          <p id="agent-name-hint" className="text-[11px] text-muted-foreground">Unique; letters, digits, dots, dashes, underscores. Belongs to the client selected in the top bar.</p>
        </form>
      </CardContent>
      <AgentTokenDialog issued={issued} origin={origin} onClose={() => setIssued(null)} />
    </Card>
  );
}
