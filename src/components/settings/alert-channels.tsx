"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Save } from "lucide-react";
import { toast } from "sonner";

import { saveMessagingSettingsAction } from "@/app/(app)/settings/actions";
import type { MessagingSettings } from "@/lib/settings";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { unwrap } from "@/lib/action-result";

interface Props {
  initial: MessagingSettings;
  ready: Record<"email" | "sms" | "whatsapp", { ready: boolean; reason?: string }>;
  counts: { sent: number; failed: number; skipped: number; pending: number };
  canEdit: boolean;
}

export function AlertChannels({ initial, ready, counts, canEdit }: Props) {
  const router = useRouter();
  const [m, setM] = React.useState(initial);
  const save = useMutation({ mutationFn: () => unwrap(saveMessagingSettingsAction(m)), onSuccess: () => { toast.success("Alert channels saved"); router.refresh(); }, onError: (e: Error) => toast.error(e.message) });
  const field = (k: keyof MessagingSettings, label: string, placeholder: string) => (
    <div className="grid gap-1.5">
      <Label htmlFor={`msg-${k}`} className="text-xs">{label}</Label>
      <Input id={`msg-${k}`} className="h-8 text-xs" placeholder={placeholder} disabled={!canEdit} value={String(m[k])} onChange={(e) => setM({ ...m, [k]: e.target.value })} />
    </div>
  );
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-2 text-xs">
        {(["email", "sms", "whatsapp"] as const).map((c) => (
          <Badge key={c} variant={ready[c].ready ? "success" : "outline"} title={ready[c].reason}>{c === "email" ? "Email" : c === "sms" ? "SMS" : "WhatsApp"}: {ready[c].ready ? "ready" : "not set up"}</Badge>
        ))}
        <span className="text-muted-foreground">Last 24 hours: {counts.sent} sent · {counts.pending} waiting · {counts.failed} failed · {counts.skipped} skipped</span>
      </div>
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="grid gap-1.5">
          <Label htmlFor="msg-provider" className="text-xs">SMS and WhatsApp through</Label>
          <NativeSelect id="msg-provider" className="h-8 text-xs" disabled={!canEdit} value={m.provider} onChange={(e) => setM({ ...m, provider: e.target.value as MessagingSettings["provider"] })}>
            <option value="none">Not set up</option>
            <option value="twilio">Twilio</option>
            <option value="webhook">Our own gateway (signed webhook)</option>
          </NativeSelect>
        </div>
        {m.provider === "twilio" && field("smsFrom", "SMS sender number", "+14155550100")}
        {m.provider === "twilio" && field("whatsappFrom", "WhatsApp sender number", "+14155238886")}
        {m.provider === "twilio" && field("whatsappTemplate", "WhatsApp template (Content SID, optional)", "HX…")}
        {m.provider === "webhook" && field("webhookUrl", "Gateway URL", "https://sms-gateway.example/helios")}
        <div className="grid gap-1.5">
          <Label htmlFor="msg-cap" className="text-xs">Most alerts per person per hour</Label>
          <Input id="msg-cap" type="number" min={1} max={200} className="h-8 text-xs" disabled={!canEdit} value={m.maxPerUserPerHour} onChange={(e) => setM({ ...m, maxPerUserPerHour: Math.min(200, Math.max(1, Number(e.target.value) || 20)) })} />
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        {m.provider === "twilio"
          ? "The Twilio account goes under provider keys below. A WhatsApp message that starts a conversation needs an approved template: set its Content SID, with {{1}} for the alert and {{2}} for the link; without one, HELIOS sends plain text, which WhatsApp only delivers inside a conversation the person opened in the last 24 hours."
          : m.provider === "webhook"
            ? "HELIOS posts { id, channel, to, text, subject, link } as JSON, signed with X-Helios-Timestamp and X-Helios-Signature (HMAC-SHA256 of \"timestamp.body\" with the signing secret under provider keys). Use it for a DLT-registered Indian SMS provider or a WhatsApp Business provider of your choice."
            : "Email alerts use the outgoing mail server under provider keys. Pick a provider to also send SMS and WhatsApp."}
      </p>
      {canEdit && <Button size="sm" className="w-fit" onClick={() => save.mutate()} disabled={save.isPending}>{save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save</Button>}
    </div>
  );
}
