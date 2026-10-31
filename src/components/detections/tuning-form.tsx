"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Plus } from "lucide-react";
import { toast } from "sonner";

import { addTuningAction } from "@/app/(app)/detections/actions";
import { TUNING_FIELDS, TUNING_KINDS, TUNING_OPS, type TuningField, type TuningKind, type TuningOp } from "@/lib/detections/tuning";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { unwrap } from "@/lib/action-result";

interface Props {
  tenants: Array<{ id: string; name: string }>;
  targets: Array<{ value: string; label: string }>;
}

export function TuningForm({ tenants, targets }: Props) {
  const router = useRouter();
  const [tenantId, setTenantId] = React.useState(tenants[0]?.id ?? "");
  const [target, setTarget] = React.useState(targets[0]?.value ?? "*");
  const [kind, setKind] = React.useState<TuningKind>("exclude");
  const [field, setField] = React.useState<TuningField>("host");
  const [op, setOp] = React.useState<TuningOp>("equals");
  const [value, setValue] = React.useState("");
  const [severity, setSeverity] = React.useState("LOW");
  const [reason, setReason] = React.useState("");
  const [expires, setExpires] = React.useState("");
  const add = useMutation({
    mutationFn: () => unwrap(addTuningAction({ tenantId, target, kind, field: kind === "exclude" ? field : null, op: kind === "exclude" ? op : null, value: kind === "exclude" ? value : null, severity: kind === "severity" ? (severity as "LOW") : null, reason, expiresAt: expires || null })),
    onSuccess: () => { toast.success("Tuning added"); setValue(""); setReason(""); setExpires(""); router.refresh(); },
    onError: (e: Error) => toast.error(e.message),
  });
  if (!tenants.length) return <p className="text-sm text-muted-foreground">Add a client first.</p>;
  const row = (label: string, id: string, el: React.ReactNode) => (
    <div className="grid gap-1.5"><Label htmlFor={id} className="text-xs">{label}</Label>{el}</div>
  );
  return (
    <div className="flex flex-col gap-3">
      <div className="grid gap-2 sm:grid-cols-3">
        {row("Client", "tn-client", <NativeSelect id="tn-client" className="h-8 text-xs" value={tenantId} onChange={(e) => setTenantId(e.target.value)}>{tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</NativeSelect>)}
        {row("Detector or rule", "tn-target", <NativeSelect id="tn-target" className="h-8 text-xs" value={target} onChange={(e) => setTarget(e.target.value)}><option value="*">Every detector and rule</option>{targets.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}</NativeSelect>)}
        {row("What to do", "tn-kind", <NativeSelect id="tn-kind" className="h-8 text-xs" value={kind} onChange={(e) => setKind(e.target.value as TuningKind)}>{Object.entries(TUNING_KINDS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</NativeSelect>)}
      </div>
      {kind === "exclude" && (
        <div className="grid gap-2 sm:grid-cols-3">
          {row("Where", "tn-field", <NativeSelect id="tn-field" className="h-8 text-xs" value={field} onChange={(e) => setField(e.target.value as TuningField)}>{Object.entries(TUNING_FIELDS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</NativeSelect>)}
          {row("Test", "tn-op", <NativeSelect id="tn-op" className="h-8 text-xs" value={op} onChange={(e) => setOp(e.target.value as TuningOp)}>{Object.entries(TUNING_OPS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</NativeSelect>)}
          {row("Value", "tn-value", <Input id="tn-value" className="h-8 text-xs" placeholder="BUILD-SRV-01" value={value} onChange={(e) => setValue(e.target.value)} />)}
        </div>
      )}
      {kind === "severity" && (
        <div className="grid gap-2 sm:grid-cols-3">
          {row("Severity", "tn-sev", <NativeSelect id="tn-sev" className="h-8 text-xs" value={severity} onChange={(e) => setSeverity(e.target.value)}>{["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => <option key={s} value={s}>{s.toLowerCase()}</option>)}</NativeSelect>)}
        </div>
      )}
      <div className="grid gap-2 sm:grid-cols-[1fr_12rem]">
        {row("Why (shown to everyone reviewing it)", "tn-reason", <Input id="tn-reason" className="h-8 text-xs" placeholder="Nightly backup job runs encoded PowerShell; confirmed with the client's IT on 26 Oct" value={reason} onChange={(e) => setReason(e.target.value)} />)}
        {row("Expires (optional)", "tn-exp", <Input id="tn-exp" type="date" className="h-8 text-xs" value={expires} onChange={(e) => setExpires(e.target.value)} />)}
      </div>
      <Button size="sm" className="w-fit" disabled={add.isPending || !reason.trim()} onClick={() => add.mutate()}>{add.isPending ? <Loader2 className="animate-spin" /> : <Plus />} Add tuning</Button>
    </div>
  );
}
