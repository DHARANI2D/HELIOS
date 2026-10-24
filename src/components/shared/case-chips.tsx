import { Bot, Clock, Layers, ShieldCheck, TimerOff } from "lucide-react";
import type { SecurityDomain } from "@prisma/client";

import { Badge } from "@/components/ui/badge";
import { DOMAIN_LABEL } from "@/lib/rbac";
import { slaState } from "@/lib/plans";
import { cn } from "@/lib/utils";

function minutesLabel(ms: number) {
  const m = Math.round(Math.abs(ms) / 60_000);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.round(h / 24)}d`;
}

// `now` comes from the server render so the chip is stable through hydration.
export function SlaChip({ createdAt, slaDueAt, acknowledgedAt, now, className }: { createdAt: Date; slaDueAt: Date | null; acknowledgedAt: Date | null; now: Date; className?: string }) {
  const state = slaState({ createdAt, slaDueAt, acknowledgedAt }, now);
  if (state === "none") return null;
  if (state === "met") {
    return (
      <Badge variant="success" className={className} title="Acknowledged within SLA">
        <ShieldCheck /> SLA met
      </Badge>
    );
  }
  if (state === "breached") {
    const over = acknowledgedAt ? acknowledgedAt.getTime() - slaDueAt!.getTime() : now.getTime() - slaDueAt!.getTime();
    return (
      <Badge variant="destructive" className={className} title={`Acknowledge-by ${slaDueAt!.toISOString()}`}>
        <TimerOff /> SLA breached {minutesLabel(over)}
      </Badge>
    );
  }
  return (
    <Badge variant={state === "at_risk" ? "warning" : "outline"} className={cn("tabular", className)} title={`Acknowledge-by ${slaDueAt!.toISOString()}`}>
      <Clock /> {minutesLabel(slaDueAt!.getTime() - now.getTime())} to ack
    </Badge>
  );
}

export function TierBadge({ tier }: { tier: number }) {
  return (
    <Badge variant="soft" title={`Escalation tier ${tier}`}>
      <Layers /> T{tier}
    </Badge>
  );
}

export function DomainBadge({ domain }: { domain: SecurityDomain | null }) {
  if (!domain) return null;
  return <Badge variant="outline" className="font-normal text-muted-foreground">{DOMAIN_LABEL[domain]}</Badge>;
}

const AI_LABEL: Record<string, string> = { queued: "AI queued", running: "AI analyzing", completed: "AI triaged", failed: "AI failed", skipped: "AI skipped" };

export function AiStatusBadge({ status }: { status: string | null }) {
  if (!status || status === "skipped") return null;
  return (
    <Badge variant={status === "failed" ? "destructive" : "ai"}>
      <Bot className={cn(status === "running" && "animate-pulse")} /> {AI_LABEL[status] ?? status}
    </Badge>
  );
}
