"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Building2, Loader2, MessageSquare, Share2, TrendingUp, Users } from "lucide-react";
import { toast } from "sonner";

import { escalateCaseAction, shareCaseAction } from "@/app/(app)/cases/actions";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";
import type { TeamMember } from "@/components/cases/triage-panel";

const TIERS = [
  { value: 1, label: "Tier 1 · triage" },
  { value: 2, label: "Tier 2 · analysis" },
  { value: 3, label: "Tier 3 · incident response" },
];

interface Props {
  caseId: string;
  tier: number;
  team: TeamMember[];
  hasClient: boolean;
  canEscalate: boolean;
  canShare: boolean;
  canAssignOthers: boolean;
}

export function CollabActions({ caseId, tier, team, hasClient, canEscalate, canShare, canAssignOthers }: Props) {
  const router = useRouter();
  const [mode, setMode] = React.useState<"escalate" | "share" | null>(null);
  const [toTier, setToTier] = React.useState(Math.min(3, tier + 1));
  const [assignee, setAssignee] = React.useState("");
  const [note, setNote] = React.useState("");
  const [target, setTarget] = React.useState<"teammates" | "client" | "chat">("teammates");
  const [picked, setPicked] = React.useState<string[]>([]);

  const close = () => {
    setMode(null);
    setNote("");
    setPicked([]);
    setAssignee("");
  };
  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed");

  const escalate = useMutation({
    mutationFn: () => escalateCaseAction(caseId, { tier: toTier, assigneeId: assignee || undefined, note }),
    onSuccess: () => {
      toast.success(`Moved to tier ${toTier}`);
      close();
      router.refresh();
    },
    onError,
  });
  const share = useMutation({
    mutationFn: () => shareCaseAction(caseId, { target, userIds: picked, note }),
    onSuccess: (summary) => {
      toast.success(summary);
      close();
      router.refresh();
    },
    onError,
  });

  return (
    <>
      <div className="grid grid-cols-2 gap-2">
        {canEscalate && (
          <Button variant="outline" size="sm" onClick={() => setMode("escalate")}>
            <TrendingUp /> Escalate
          </Button>
        )}
        <Button variant="outline" size="sm" onClick={() => setMode("share")} className={cn(!canEscalate && "col-span-2")}>
          <Share2 /> Share
        </Button>
      </div>

      <Dialog open={mode === "escalate"} onOpenChange={(o) => !o && close()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Escalate or hand off</DialogTitle>
            <DialogDescription>Moves the case to another tier&apos;s queue. Leave the assignee empty to notify everyone in that tier.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-1.5">
              <Label>Tier</Label>
              <NativeSelect value={toTier} onChange={(e) => setToTier(Number(e.target.value))}>
                {TIERS.map((t) => (
                  <option key={t.value} value={t.value}>{t.label}{t.value === tier ? " (current)" : ""}</option>
                ))}
              </NativeSelect>
            </div>
            {canAssignOthers && (
              <div className="grid gap-1.5">
                <Label>Hand off to</Label>
                <NativeSelect value={assignee} onChange={(e) => setAssignee(e.target.value)}>
                  <option value="">Anyone in the tier</option>
                  {team.map((m) => (
                    <option key={m.id} value={m.id}>{m.name} · {m.role}</option>
                  ))}
                </NativeSelect>
              </div>
            )}
            <div className="grid gap-1.5">
              <Label>Hand-off note</Label>
              <Textarea value={note} onChange={(e) => setNote(e.target.value)} placeholder="What you found, what's left to check…" className="min-h-24" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={close}>Cancel</Button>
            <Button onClick={() => escalate.mutate()} disabled={escalate.isPending}>
              {escalate.isPending ? <Loader2 className="animate-spin" /> : <TrendingUp />}
              {toTier > tier ? "Escalate" : toTier < tier ? "De-escalate" : "Hand off"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={mode === "share"} onOpenChange={(o) => !o && close()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Share this case</DialogTitle>
            <DialogDescription>Pull in teammates, update the client, or post to a chat channel. Every share is recorded on the timeline.</DialogDescription>
          </DialogHeader>
          <div className="grid grid-cols-3 gap-2">
            {(
              [
                { key: "teammates", label: "Teammates", icon: Users, disabled: false },
                { key: "client", label: "Client", icon: Building2, disabled: !canShare || !hasClient },
                { key: "chat", label: "Chat channel", icon: MessageSquare, disabled: !canShare },
              ] as const
            ).map((o) => (
              <button
                key={o.key}
                type="button"
                disabled={o.disabled}
                onClick={() => setTarget(o.key)}
                className={cn(
                  "flex flex-col items-center gap-1 rounded-lg border p-3 text-xs transition-colors hover:bg-accent disabled:cursor-not-allowed disabled:opacity-40",
                  target === o.key && "border-primary bg-primary/10 text-primary",
                )}
              >
                <o.icon className="size-4" />
                {o.label}
              </button>
            ))}
          </div>
          {target === "teammates" && (
            <div className="max-h-48 overflow-y-auto rounded-md border">
              {team.map((m) => (
                <label key={m.id} className="flex cursor-pointer items-center gap-2 border-b px-3 py-2 text-sm last:border-b-0 hover:bg-accent/50">
                  <input
                    type="checkbox"
                    checked={picked.includes(m.id)}
                    onChange={(e) => setPicked((p) => (e.target.checked ? [...p, m.id] : p.filter((x) => x !== m.id)))}
                  />
                  <span>{m.name}</span>
                  <span className="ml-auto text-xs text-muted-foreground">{m.role}</span>
                </label>
              ))}
            </div>
          )}
          {target === "client" && <p className="text-xs text-muted-foreground">Posts a client-visible update and notifies the client&apos;s users. Internal comments stay internal.</p>}
          {target === "chat" && <p className="text-xs text-muted-foreground">Posts to the client&apos;s Slack/Teams channel (or the SOC channel) from Tools &amp; Integrations.</p>}
          <Textarea value={note} onChange={(e) => setNote(e.target.value)} placeholder={target === "client" ? "Message to the client…" : "Add a note (optional)"} className="min-h-20" />
          <DialogFooter>
            <Button variant="ghost" onClick={close}>Cancel</Button>
            <Button onClick={() => share.mutate()} disabled={share.isPending || (target === "teammates" && picked.length === 0)}>
              {share.isPending ? <Loader2 className="animate-spin" /> : <Share2 />}
              Share
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
