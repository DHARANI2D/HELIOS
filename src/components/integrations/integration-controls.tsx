"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { KeyRound, Loader2, PlugZap, Settings2 } from "lucide-react";
import { toast } from "sonner";
import type { UserRole } from "@prisma/client";

import { rotateTokenAction, setIntegrationEnabledAction, testConnectorAction, updateIntegrationAction } from "@/app/(app)/integrations/actions";
import { ROLES } from "@/lib/rbac";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { CopyField } from "@/components/integrations/onboard-wizard";

const STAFF_ROLES: UserRole[] = ["SOC_MANAGER", "TRIAGE_ANALYST", "ANALYST", "INCIDENT_RESPONDER", "THREAT_HUNTER", "DETECTION_ENGINEER", "AUDITOR"];

interface Props {
  id: string;
  name: string;
  enabled: boolean;
  pushes: boolean;
  hasActions: boolean;
  allowedRoles: UserRole[];
  assignedUserIds: string[];
  responseWebhookUrl: string;
  team: Array<{ id: string; name: string }>;
  origin: string;
  isClient: boolean;
}

export function IntegrationControls(props: Props) {
  const router = useRouter();
  const [token, setToken] = React.useState<{ token: string; ingestPath: string } | null>(null);
  const [editing, setEditing] = React.useState(false);
  const [roles, setRoles] = React.useState(props.allowedRoles);
  const [users, setUsers] = React.useState(props.assignedUserIds);
  const [responseUrl, setResponseUrl] = React.useState(props.responseWebhookUrl);
  const [secret, setSecret] = React.useState("");
  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed");

  const rotate = useMutation({ mutationFn: () => rotateTokenAction(props.id), onSuccess: (r) => { setToken(r); router.refresh(); }, onError });
  const test = useMutation({
    mutationFn: () => testConnectorAction(props.id),
    onSuccess: (r) => {
      toast.success(`Connector answered: ${r.message}`);
      router.refresh();
    },
    onError,
  });
  const toggle = useMutation({ mutationFn: (on: boolean) => setIntegrationEnabledAction(props.id, on), onSuccess: () => router.refresh(), onError });
  const save = useMutation({
    mutationFn: () => updateIntegrationAction(props.id, { allowedRoles: roles, assignedUserIds: users, responseWebhookUrl: responseUrl, webhookSecret: secret || undefined }),
    onSuccess: () => {
      toast.success("Access updated");
      setEditing(false);
      router.refresh();
    },
    onError,
  });

  return (
    <div className="flex items-center justify-end gap-1">
      {props.hasActions && props.responseWebhookUrl && (
        <Button size="sm" variant="ghost" className="h-7" onClick={() => test.mutate()} disabled={test.isPending || !props.enabled} title="Send a signed PING to the response connector; nothing is acted on">
          {test.isPending ? <Loader2 className="animate-spin" /> : <PlugZap />} Test connector
        </Button>
      )}
      {props.pushes && (
        <Button size="sm" variant="ghost" className="h-7" onClick={() => rotate.mutate()} disabled={rotate.isPending} title="Issue a new ingest token">
          {rotate.isPending ? <Loader2 className="animate-spin" /> : <KeyRound />} Token
        </Button>
      )}
      <Button size="icon" variant="ghost" className="size-7" aria-label="Access and connector" onClick={() => setEditing(true)}>
        <Settings2 />
      </Button>
      <Switch checked={props.enabled} onCheckedChange={(on) => toggle.mutate(on)} aria-label="Enabled" />

      <Dialog open={!!token} onOpenChange={(o) => !o && setToken(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New ingest token for {props.name}</DialogTitle>
            <DialogDescription>The previous token stopped working. This one is shown once.</DialogDescription>
          </DialogHeader>
          {token && (
            <div className="grid gap-3">
              <CopyField label="Ingest URL" value={`${props.origin}${token.ingestPath}`} />
              <CopyField label="Bearer token" value={token.token} />
            </div>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={editing} onOpenChange={setEditing}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{props.name}</DialogTitle>
            <DialogDescription>Who can use this tool, and where approved response actions are sent.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4">
            {!props.isClient && (
              <div className="grid gap-1.5">
                <Label>Roles</Label>
                <div className="flex flex-wrap gap-1.5">
                  {STAFF_ROLES.map((r) => {
                    const on = roles.includes(r);
                    return (
                      <button key={r} type="button" onClick={() => setRoles(on ? roles.filter((x) => x !== r) : [...roles, r])} className={cn("rounded-full border px-2.5 py-0.5 text-xs hover:bg-accent", on && "border-primary bg-primary/15 text-primary")}>
                        {ROLES[r].label}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
            {!props.isClient && props.team.length > 0 && (
              <div className="grid gap-1.5">
                <Label>People</Label>
                <div className="flex max-h-28 flex-wrap gap-1.5 overflow-y-auto">
                  {props.team.map((m) => {
                    const on = users.includes(m.id);
                    return (
                      <button key={m.id} type="button" onClick={() => setUsers(on ? users.filter((x) => x !== m.id) : [...users, m.id])} className={cn("rounded-full border px-2.5 py-0.5 text-xs hover:bg-accent", on && "border-primary bg-primary/15 text-primary")}>
                        {m.name}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
            {props.hasActions && (
              <>
                <div className="grid gap-1.5">
                  <Label>Response connector URL</Label>
                  <Input value={responseUrl} onChange={(e) => setResponseUrl(e.target.value)} type="url" />
                </div>
                <div className="grid gap-1.5">
                  <Label>Signing secret</Label>
                  <Input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="Leave blank to keep the current secret" autoComplete="off" />
                </div>
              </>
            )}
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setEditing(false)}>Cancel</Button>
            <Button onClick={() => save.mutate()} disabled={save.isPending}>
              {save.isPending && <Loader2 className="animate-spin" />}
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
