"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Lock, LockOpen, Upload } from "lucide-react";
import { toast } from "sonner";

import { importInventoryAction, setIsolationAction, updateEndpointAction } from "@/app/(app)/endpoints/actions";
import { CONTROLS } from "@/lib/endpoints/controls";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { TenantSelect } from "@/components/shared/tenant-select";

export function IsolationButton({ id, isolated, hostname }: { id: string; isolated: boolean; hostname: string }) {
  const router = useRouter();
  const mut = useMutation({
    mutationFn: () => setIsolationAction(id, !isolated),
    onSuccess: (r) => {
      toast.success(r.manual ? `Marked ${hostname} as ${isolated ? "released" : "isolated"} — no EDR connector, so make sure it's done in the EDR console` : `${isolated ? "Released" : "Isolated"} ${hostname} — ${r.message}`);
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  return (
    <Button size="sm" variant={isolated ? "outline" : "ghost"} className="h-7" onClick={() => mut.mutate()} disabled={mut.isPending}>
      {mut.isPending ? <Loader2 className="animate-spin" /> : isolated ? <LockOpen /> : <Lock />}
      {isolated ? "Release" : "Isolate"}
    </Button>
  );
}

export function CriticalitySelect({ id, value }: { id: string; value: string }) {
  const router = useRouter();
  const mut = useMutation({
    mutationFn: (criticality: string) => updateEndpointAction(id, { criticality }),
    onSuccess: () => router.refresh(),
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  return (
    <NativeSelect value={value} onChange={(e) => mut.mutate(e.target.value)} disabled={mut.isPending} className="h-7 text-xs" aria-label="Criticality">
      <option value="standard">Standard</option>
      <option value="high">High</option>
      <option value="critical">Critical</option>
    </NativeSelect>
  );
}


export function InventoryImport({ tenants, defaultTenantId, isClient }: { tenants: Array<{ id: string; name: string }>; defaultTenantId: string | null; isClient: boolean }) {
  const router = useRouter();
  const [open, setOpen] = React.useState(false);
  const [csv, setCsv] = React.useState("");
  const [tenantId, setTenantId] = React.useState(defaultTenantId ?? "none");
  const mut = useMutation({
    mutationFn: () => importInventoryAction(csv, tenantId),
    onSuccess: (n) => {
      toast.success(`Imported ${n} endpoint${n === 1 ? "" : "s"}`);
      setOpen(false);
      setCsv("");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Import failed"),
  });
  return (
    <>
      <Button size="sm" variant="outline" onClick={() => setOpen(true)}>
        <Upload /> Import inventory
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Import asset inventory</DialogTitle>
            <DialogDescription>
              CSV with a header row: hostname, os, ip, owner, criticality (standard, high, critical), controls — each <code className="text-[11px]">control=active|degraded|missing</code>, separated by <code>;</code>, using the keys {CONTROLS.map((c) => c.key).join(", ")} — and optionally class (user, mobile, server, cloud, network, identity, iot_ot, email, apps) and type (e.g. firewall, plc, medical, cloud_vm, web_app). Rows without a class are placed by their OS. Existing hosts are updated. Export it from your RMM, MDM, EDR, CMDB or network discovery tool.
            </DialogDescription>
          </DialogHeader>
          {!isClient && <TenantSelect tenants={tenants} value={tenantId} onChange={setTenantId} />}
          <Input
            type="file"
            accept=".csv,text/csv"
            aria-label="Inventory CSV file"
            onChange={async (e) => {
              const file = e.target.files?.[0];
              if (file) setCsv(await file.text());
            }}
          />
          <Textarea value={csv} onChange={(e) => setCsv(e.target.value)} aria-label="Inventory CSV" className="min-h-40 font-mono text-xs" />
          <DialogFooter>
            <Button onClick={() => mut.mutate()} disabled={mut.isPending || !csv.trim()}>
              {mut.isPending && <Loader2 className="animate-spin" />}
              Import
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
