"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Save, Send } from "lucide-react";
import { toast } from "sonner";

import { saveAlertPrefsAction, testAlertsAction } from "@/app/(app)/account/alerts/actions";
import { ALERT_CHANNELS, ALERT_GROUPS, CHANNEL_KEYS, type AlertChannel, type AlertGroup } from "@/lib/alerts/kinds";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { unwrap } from "@/lib/action-result";

interface Props {
  email: string;
  phone: string;
  groups: Record<AlertGroup, AlertChannel[]>;
  ready: Record<AlertChannel, { ready: boolean; reason?: string }>;
}

export function AlertPrefsForm(props: Props) {
  const router = useRouter();
  const [phone, setPhone] = React.useState(props.phone);
  const [groups, setGroups] = React.useState(props.groups);
  const onError = (e: Error) => toast.error(e.message);
  const save = useMutation({ mutationFn: () => unwrap(saveAlertPrefsAction({ phone, groups })), onSuccess: () => { toast.success("Alert channels saved"); router.refresh(); }, onError });
  const test = useMutation({
    mutationFn: () => unwrap(testAlertsAction()),
    onSuccess: (results) => {
      for (const r of results) (r.ok ? toast.success : toast.error)(`${ALERT_CHANNELS[r.channel]}: ${r.message}`);
      router.refresh();
    },
    onError,
  });
  const toggle = (g: AlertGroup, c: AlertChannel, on: boolean) => setGroups((x) => ({ ...x, [g]: on ? [...new Set([...(x[g] ?? []), c])] : (x[g] ?? []).filter((y) => y !== c) }));

  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="grid gap-1.5">
          <Label className="text-xs">Email</Label>
          <p className="text-sm">{props.email}</p>
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="alert-phone" className="text-xs">Mobile number for SMS and WhatsApp</Label>
          <Input id="alert-phone" className="h-8" placeholder="+919812345678" value={phone} onChange={(e) => setPhone(e.target.value)} />
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-muted-foreground">
              <th className="py-1.5 pr-3 font-medium">Notify me about</th>
              {CHANNEL_KEYS.map((c) => <th key={c} className="px-3 py-1.5 text-center font-medium">{ALERT_CHANNELS[c]}</th>)}
            </tr>
          </thead>
          <tbody>
            {ALERT_GROUPS.map((g) => (
              <tr key={g.key} className="border-t">
                <td className="py-2 pr-3 text-xs">{g.label}</td>
                {CHANNEL_KEYS.map((c) => (
                  <td key={c} className="px-3 py-2 text-center">
                    <input type="checkbox" aria-label={`${g.label} by ${ALERT_CHANNELS[c]}`} checked={(groups[g.key] ?? []).includes(c)} onChange={(e) => toggle(g.key, c, e.target.checked)} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {CHANNEL_KEYS.filter((c) => !props.ready[c].ready).length > 0 && (
        <ul className="flex flex-col gap-0.5 text-xs text-muted-foreground">
          {CHANNEL_KEYS.filter((c) => !props.ready[c].ready).map((c) => <li key={c}>{ALERT_CHANNELS[c]} isn&apos;t available yet: {props.ready[c].reason}. Your choice is kept, and alerts start once your SOC sets it up.</li>)}
        </ul>
      )}
      <div className="flex flex-wrap gap-2">
        <Button size="sm" onClick={() => save.mutate()} disabled={save.isPending}>{save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save</Button>
        <Button size="sm" variant="outline" onClick={() => test.mutate()} disabled={test.isPending}>{test.isPending ? <Loader2 className="animate-spin" /> : <Send />} Send me a test</Button>
      </div>
    </div>
  );
}
