"use client";

import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Loader2 } from "lucide-react";
import { toast } from "sonner";
import type { CaseSeverity, CaseSource, PlaybookActionType } from "@prisma/client";

import { createPlaybookAction } from "@/app/(app)/playbooks/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const ACTION_TYPES: PlaybookActionType[] = [
  "ISOLATE_HOST",
  "BLOCK_IP",
  "NOTIFY_SLACK",
  "CREATE_TICKET",
  "KILL_PROCESS",
  "COLLECT_LOGS",
  "REVOKE_AGENT",
  "RESTORE_AGENT",
];

const SEVERITIES: CaseSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SOURCES: CaseSource[] = ["AGENT_GOVERNANCE", "SOC_INVESTIGATION", "EMAIL_ANALYSIS", "SIEM_ALERT"];

export function CreatePlaybookForm() {
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [severity, setSeverity] = React.useState<string>("any");
  const [sourceType, setSourceType] = React.useState<string>("any");
  const [autoExecute, setAutoExecute] = React.useState(false);
  const [requireApproval, setRequireApproval] = React.useState(true);
  const [selectedActions, setSelectedActions] = React.useState<Set<PlaybookActionType>>(new Set());
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () =>
      createPlaybookAction({
        name: name.trim(),
        description: description.trim(),
        severity: severity === "any" ? undefined : (severity as CaseSeverity),
        sourceType: sourceType === "any" ? undefined : (sourceType as CaseSource),
        autoExecute,
        requireApproval,
        actions: [...selectedActions].map((actionType) => ({
          name: actionType.replaceAll("_", " ").toLowerCase(),
          actionType,
          parameters: {},
        })),
      }),
    onSuccess: () => {
      toast.success("Playbook created");
      setName("");
      setDescription("");
      setSelectedActions(new Set());
      queryClient.invalidateQueries({ queryKey: ["playbooks"] });
    },
    onError: () => toast.error("Failed to create playbook"),
  });

  function toggleAction(action: PlaybookActionType) {
    setSelectedActions((prev) => {
      const next = new Set(prev);
      if (next.has(action)) next.delete(action);
      else next.add(action);
      return next;
    });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Create playbook</CardTitle>
        <CardDescription>
          Triggers on any case matching its condition — from any of the four
          modules
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!name.trim() || selectedActions.size === 0) {
              toast.error("Name and at least one action are required");
              return;
            }
            mutation.mutate();
          }}
          className="flex flex-col gap-3"
        >
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <Label>Name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Ransomware Response" />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label>Description</Label>
              <Input value={description} onChange={(e) => setDescription(e.target.value)} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label>Trigger severity</Label>
              <Select value={severity} onValueChange={setSeverity}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="any">Any severity</SelectItem>
                  {SEVERITIES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label>Trigger source</Label>
              <Select value={sourceType} onValueChange={setSourceType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="any">Any source</SelectItem>
                  {SOURCES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s.replaceAll("_", " ")}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div>
            <Label className="mb-2">Actions</Label>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {ACTION_TYPES.map((action) => (
                <button
                  type="button"
                  key={action}
                  onClick={() => toggleAction(action)}
                  className={`rounded-md border px-2 py-1.5 text-left text-xs transition-colors ${
                    selectedActions.has(action)
                      ? "border-primary bg-primary/10"
                      : "hover:bg-accent"
                  }`}
                >
                  {action.replaceAll("_", " ")}
                </button>
              ))}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-6">
            <div className="flex items-center gap-2">
              <Switch checked={autoExecute} onCheckedChange={setAutoExecute} id="auto-exec" />
              <Label htmlFor="auto-exec">Auto-execute</Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch checked={requireApproval} onCheckedChange={setRequireApproval} id="req-approval" />
              <Label htmlFor="req-approval">Require approval</Label>
            </div>
          </div>

          <Button type="submit" disabled={mutation.isPending} className="self-start">
            {mutation.isPending ? <Loader2 className="animate-spin" /> : <Plus />}
            Create playbook
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
