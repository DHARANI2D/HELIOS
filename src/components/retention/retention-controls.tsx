"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Lock, Save, Unlock } from "lucide-react";
import { toast } from "sonner";

import { placeHoldAction, releaseHoldAction, setRetentionAction } from "@/app/(app)/retention/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { unwrap } from "@/lib/action-result";

const onError = (e: Error) => toast.error(e.message);

export function RetentionForm({ tenantId, hotDays, retentionDays, minDays }: { tenantId: string; hotDays: number; retentionDays: number; minDays: number }) {
  const router = useRouter();
  const [hot, setHot] = React.useState(hotDays);
  const [total, setTotal] = React.useState(retentionDays);
  const save = useMutation({ mutationFn: () => unwrap(setRetentionAction(tenantId, { hotDays: hot, retentionDays: total })), onSuccess: () => { toast.success("Retention saved"); router.refresh(); }, onError });
  const changed = hot !== hotDays || total !== retentionDays;
  return (
    <div className="flex items-end gap-2">
      <div className="grid gap-1">
        <Label htmlFor={`hot-${tenantId}`} className="text-[11px]">Searchable (days)</Label>
        <Input id={`hot-${tenantId}`} type="number" min={7} max={730} className="h-7 w-20 text-xs" value={hot} onChange={(e) => setHot(Number(e.target.value) || 0)} />
      </div>
      <div className="grid gap-1">
        <Label htmlFor={`total-${tenantId}`} className="text-[11px]">Kept (days, min {minDays})</Label>
        <Input id={`total-${tenantId}`} type="number" min={minDays} max={3650} className="h-7 w-24 text-xs" value={total} onChange={(e) => setTotal(Number(e.target.value) || 0)} />
      </div>
      {changed && <Button size="sm" className="h-7" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? <Loader2 className="animate-spin" /> : <Save />}</Button>}
    </div>
  );
}

export function HoldForm({ tenants }: { tenants: Array<{ id: string; name: string }> }) {
  const router = useRouter();
  const [tenantId, setTenantId] = React.useState(tenants[0]?.id ?? "");
  const [reason, setReason] = React.useState("");
  const [from, setFrom] = React.useState("");
  const [to, setTo] = React.useState("");
  const [caseId, setCaseId] = React.useState("");
  const place = useMutation({ mutationFn: () => unwrap(placeHoldAction({ tenantId, reason, from, to: to || undefined, caseId: caseId || undefined })), onSuccess: () => { toast.success("Legal hold placed"); setReason(""); setCaseId(""); router.refresh(); }, onError });
  if (!tenants.length) return null;
  return (
    <div className="grid gap-2 sm:grid-cols-[12rem_1fr_9rem_9rem_10rem_auto] sm:items-end">
      <div className="grid gap-1"><Label htmlFor="hold-client" className="text-xs">Client</Label><NativeSelect id="hold-client" className="h-8 text-xs" value={tenantId} onChange={(e) => setTenantId(e.target.value)}>{tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</NativeSelect></div>
      <div className="grid gap-1"><Label htmlFor="hold-reason" className="text-xs">Why (matter, request or reference)</Label><Input id="hold-reason" className="h-8 text-xs" value={reason} onChange={(e) => setReason(e.target.value)} /></div>
      <div className="grid gap-1"><Label htmlFor="hold-from" className="text-xs">From</Label><Input id="hold-from" type="date" className="h-8 text-xs" value={from} onChange={(e) => setFrom(e.target.value)} /></div>
      <div className="grid gap-1"><Label htmlFor="hold-to" className="text-xs">To (blank: open)</Label><Input id="hold-to" type="date" className="h-8 text-xs" value={to} onChange={(e) => setTo(e.target.value)} /></div>
      <div className="grid gap-1"><Label htmlFor="hold-case" className="text-xs">Case id (optional)</Label><Input id="hold-case" className="h-8 text-xs" value={caseId} onChange={(e) => setCaseId(e.target.value)} /></div>
      <Button size="sm" disabled={place.isPending || !reason.trim() || !from} onClick={() => place.mutate()}>{place.isPending ? <Loader2 className="animate-spin" /> : <Lock />} Hold</Button>
    </div>
  );
}

export function ReleaseHold({ id }: { id: string }) {
  const router = useRouter();
  const release = useMutation({
    mutationFn: async () => {
      const reason = prompt("Why is the hold released?");
      if (!reason) throw new Error("A release needs a reason");
      return unwrap(releaseHoldAction(id, reason));
    },
    onSuccess: () => { toast.success("Hold released"); router.refresh(); },
    onError,
  });
  return <Button size="sm" variant="ghost" className="h-7 text-xs" disabled={release.isPending} onClick={() => release.mutate()}>{release.isPending ? <Loader2 className="animate-spin" /> : <Unlock />} Release</Button>;
}
