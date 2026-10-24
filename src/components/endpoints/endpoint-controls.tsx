"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Lock, LockOpen, Upload } from "lucide-react";
import { toast } from "sonner";

import { importInventoryAction, setIsolationAction, updateEndpointAction } from "@/app/(app)/endpoints/actions";
import { Button } from "@/components/ui/button";
import { NativeSelect } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { TenantSelect } from "@/components/shared/tenant-select";

export function IsolationButton({ id, isolated, hostname }: { id: string; isolated: boolean; hostname: string }) {
  const router = useRouter();
  const mut = useMutation({
    mutationFn: () => setIsolationAction(id, !isolated),
    onSuccess: (r) => {
      toast.success(`${isolated ? "Released" : "Isolated"} ${hostname}${r.simulated ? " (recorded — no EDR connector, carry it out in the console)" : ` — ${r.message}`}`);
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

const SAMPLE = `hostname,os,ip,owner,criticality,controls
FIN-LAPTOP-07,Windows 11,10.20.4.17,j.alvarez,standard,edr=active;av=active;disk_encryption=active;patching=degraded;host_firewall=active
DC-01,Windows Server 2022,10.20.0.10,it-ops,critical,edr=active;av=active;patching=active;host_firewall=active;backup=active
MAC-DESIGN-03,macOS 15,10.20.6.33,l.nguyen,standard,edr=missing;av=active;disk_encryption=active;mdm=active`;

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
            <DialogTitle>Import endpoint inventory</DialogTitle>
            <DialogDescription>
              CSV with a header row: hostname, os, ip, owner, criticality, controls (control=active|degraded|missing, separated by ;). Existing hosts are updated.
            </DialogDescription>
          </DialogHeader>
          {!isClient && <TenantSelect tenants={tenants} value={tenantId} onChange={setTenantId} />}
          <Textarea value={csv} onChange={(e) => setCsv(e.target.value)} placeholder={SAMPLE} className="min-h-40 font-mono text-xs" />
          <DialogFooter>
            <Button variant="ghost" onClick={() => setCsv(SAMPLE)}>Load example</Button>
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
