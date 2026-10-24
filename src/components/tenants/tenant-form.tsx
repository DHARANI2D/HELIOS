"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Building2, Loader2, Pencil, Plus } from "lucide-react";
import { toast } from "sonner";
import type { AiAutonomy } from "@prisma/client";

import { saveTenantAction, setAiCapAction } from "@/app/(app)/tenants/actions";
import { AUTONOMY_LABEL, AUTONOMY_ORDER } from "@/lib/ai/catalog";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";

export interface TenantDraft {
  name: string;
  industry: string;
  planId: string | null;
  status: "ONBOARDING" | "ACTIVE" | "SUSPENDED";
  contactName: string;
  contactEmail: string;
  endpointsLicensed: number;
  usersLicensed: number;
  notes: string;
}

const EMPTY: TenantDraft = { name: "", industry: "", planId: null, status: "ONBOARDING", contactName: "", contactEmail: "", endpointsLicensed: 0, usersLicensed: 0, notes: "" };

export interface PlanOption {
  id: string;
  name: string;
  tagline: string | null;
}

export function TenantFormButton({ tenantId, initial, plans }: { tenantId?: string; initial?: TenantDraft; plans: PlanOption[] }) {
  const router = useRouter();
  const [open, setOpen] = React.useState(false);
  const [d, setD] = React.useState<TenantDraft>(initial ?? EMPTY);
  const save = useMutation({
    mutationFn: () => saveTenantAction(d, tenantId),
    onSuccess: (r) => {
      toast.success(tenantId ? "Client updated" : "Client created");
      setOpen(false);
      if (!tenantId) router.push(`/tenants/${r.id}`);
      else router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  return (
    <>
      <Button size="sm" variant={tenantId ? "outline" : "default"} onClick={() => setOpen(true)}>
        {tenantId ? <Pencil /> : <Plus />}
        {tenantId ? "Edit client" : "New client"}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><Building2 className="size-4" /> {tenantId ? "Edit client" : "New client"}</DialogTitle>
            <DialogDescription>The plan sets the SLA every case for this client runs on, and the default AI consent.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-1.5 sm:col-span-2">
              <Label>Organization name</Label>
              <Input value={d.name} onChange={(e) => setD({ ...d, name: e.target.value })} />
            </div>
            <div className="grid gap-1.5">
              <Label>Industry</Label>
              <Input value={d.industry} onChange={(e) => setD({ ...d, industry: e.target.value })} />
            </div>
            <div className="grid gap-1.5">
              <Label>Status</Label>
              <NativeSelect value={d.status} onChange={(e) => setD({ ...d, status: e.target.value as TenantDraft["status"] })}>
                <option value="ONBOARDING">Onboarding</option>
                <option value="ACTIVE">Active</option>
                <option value="SUSPENDED">Suspended (blocks client logins)</option>
              </NativeSelect>
            </div>
            <div className="grid gap-1.5 sm:col-span-2">
              <Label>Service plan</Label>
              <NativeSelect value={d.planId ?? ""} onChange={(e) => setD({ ...d, planId: e.target.value || null })}>
                <option value="">No plan yet (no SLA)</option>
                {plans.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}{p.tagline ? ` — ${p.tagline}` : ""}</option>
                ))}
              </NativeSelect>
              {plans.length === 0 && <p className="text-[11px] text-muted-foreground">No plans defined yet — create them in Build &amp; Price → Pricing setup.</p>}
            </div>
            <div className="grid gap-1.5">
              <Label>Endpoints licensed</Label>
              <Input type="number" min={0} value={d.endpointsLicensed} onChange={(e) => setD({ ...d, endpointsLicensed: Number(e.target.value) })} />
            </div>
            <div className="grid gap-1.5">
              <Label>Users licensed</Label>
              <Input type="number" min={0} value={d.usersLicensed} onChange={(e) => setD({ ...d, usersLicensed: Number(e.target.value) })} />
            </div>
            <div className="grid gap-1.5">
              <Label>Primary contact</Label>
              <Input value={d.contactName} onChange={(e) => setD({ ...d, contactName: e.target.value })} />
            </div>
            <div className="grid gap-1.5">
              <Label>Contact email</Label>
              <Input type="email" value={d.contactEmail} onChange={(e) => setD({ ...d, contactEmail: e.target.value })} />
            </div>
            <div className="grid gap-1.5 sm:col-span-2">
              <Label>Notes</Label>
              <Textarea value={d.notes} onChange={(e) => setD({ ...d, notes: e.target.value })} className="min-h-16" aria-describedby="tenant-notes-hint" />
              <p id="tenant-notes-hint" className="text-[11px] text-muted-foreground">Escalation contacts, maintenance windows, business-critical systems.</p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={() => save.mutate()} disabled={save.isPending || d.name.trim().length < 2}>
              {save.isPending && <Loader2 className="animate-spin" />}
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

export function AiConsentSelect({ tenantId, value, canEdit }: { tenantId: string; value: AiAutonomy; canEdit: boolean }) {
  const router = useRouter();
  const mut = useMutation({
    mutationFn: (cap: string) => setAiCapAction(tenantId, cap),
    onSuccess: () => {
      toast.success("AI consent updated");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  return (
    <NativeSelect value={value} onChange={(e) => mut.mutate(e.target.value)} disabled={!canEdit || mut.isPending} aria-label="AI consent">
      {AUTONOMY_ORDER.map((a) => (
        <option key={a} value={a}>{AUTONOMY_LABEL[a]}</option>
      ))}
    </NativeSelect>
  );
}
