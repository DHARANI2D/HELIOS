"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Layers, Loader2, Pencil, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import type { AiAutonomy, CaseSeverity } from "@prisma/client";

import { deletePlanAction, savePlanAction, type PlanInput } from "@/app/(app)/pricing/actions";
import { AUTONOMY_LABEL, AUTONOMY_ORDER } from "@/lib/ai/catalog";
import { PLAN_FEATURES, PLAN_FEATURE_LABEL, SEVERITIES, formatMinutes, type ServicePlan } from "@/lib/plans";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { EmptyState } from "@/components/shared/empty-state";
import { parseAmount } from "@/components/pricing/price-book";

type Draft = {
  key: string;
  name: string;
  tagline: string;
  coverage: string;
  ack: Record<CaseSeverity, string>;
  contain: Record<CaseSeverity, string>;
  irRetainerHours: string;
  pricePerEndpoint: string;
  costPerEndpoint: string;
  onboardingMinimum: string;
  defaultAutonomyCap: AiAutonomy;
  features: Record<string, { on: boolean; text: string }>;
  active: boolean;
  sortOrder: string;
};

const s = (n: number | null | undefined) => (n == null ? "" : String(n));
const bySeverity = (f: (sev: CaseSeverity) => string) => Object.fromEntries(SEVERITIES.map((sev) => [sev, f(sev)])) as Record<CaseSeverity, string>;

function toDraft(p?: ServicePlan): Draft {
  return {
    key: p?.key ?? "",
    name: p?.name ?? "",
    tagline: p?.tagline ?? "",
    coverage: p?.coverage ?? "",
    ack: bySeverity((sev) => s(p?.ackMinutes[sev])),
    contain: bySeverity((sev) => s(p?.containMinutes[sev])),
    irRetainerHours: s(p?.irRetainerHours ?? 0),
    pricePerEndpoint: s(p?.pricePerEndpoint),
    costPerEndpoint: s(p?.costPerEndpoint),
    onboardingMinimum: s(p?.onboardingMinimum),
    defaultAutonomyCap: p?.defaultAutonomyCap ?? "CONTAIN_WITH_APPROVAL",
    features: Object.fromEntries(
      PLAN_FEATURES.map((f) => {
        const v = p?.features[f];
        return [f, { on: v === true || typeof v === "string", text: typeof v === "string" ? v : "" }];
      }),
    ),
    active: p?.active ?? true,
    sortOrder: s(p?.sortOrder ?? 0),
  };
}

function toInput(d: Draft): PlanInput {
  const num = (v: string, label: string) => {
    const n = parseAmount(v);
    if (n === "invalid") throw new Error(`${label}: enter a number or leave it empty`);
    return n;
  };
  const mins = (v: string, label: string) => {
    const n = num(v, label);
    return n == null ? null : Math.round(n);
  };
  return {
    key: d.key || d.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""),
    name: d.name,
    tagline: d.tagline.trim() || null,
    coverage: d.coverage,
    ackMinutes: Object.fromEntries(SEVERITIES.map((sev) => [sev, mins(d.ack[sev], `Acknowledge ${sev.toLowerCase()}`)])),
    containMinutes: Object.fromEntries(SEVERITIES.map((sev) => [sev, mins(d.contain[sev], `Contain ${sev.toLowerCase()}`)])),
    irRetainerHours: Math.round(num(d.irRetainerHours, "IR retainer") ?? 0),
    pricePerEndpoint: num(d.pricePerEndpoint, "Price per endpoint"),
    costPerEndpoint: num(d.costPerEndpoint, "Cost per endpoint"),
    onboardingMinimum: num(d.onboardingMinimum, "Onboarding minimum"),
    defaultAutonomyCap: d.defaultAutonomyCap,
    features: Object.fromEntries(PLAN_FEATURES.map((f) => [f, d.features[f].on ? d.features[f].text.trim() || true : false])),
    active: d.active,
    sortOrder: Math.round(num(d.sortOrder, "Order") ?? 0),
  };
}

function PlanDialog({ plan, open, onOpenChange }: { plan?: ServicePlan; open: boolean; onOpenChange: (v: boolean) => void }) {
  const router = useRouter();
  const [d, setD] = React.useState<Draft>(() => toDraft(plan));
  const save = useMutation({
    mutationFn: () => savePlanAction(toInput(d), plan?.id),
    onSuccess: () => {
      toast.success(plan ? "Plan updated" : "Plan created");
      onOpenChange(false);
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  const field = (label: string, value: string, onChange: (v: string) => void, hint?: string) => (
    <div className="grid gap-1.5">
      <Label className="text-xs">{label}</Label>
      <Input value={value} onChange={(e) => onChange(e.target.value)} inputMode="decimal" className="tabular" />
      {hint && <p className="text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  );
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><Layers className="size-4" /> {plan ? `Edit ${plan.name}` : "New service plan"}</DialogTitle>
          <DialogDescription>A client&apos;s plan sets the SLA its cases run on, the most autonomy its AI agents start with, and what Build &amp; Price charges.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="grid gap-1.5 sm:col-span-2">
              <Label className="text-xs">Name</Label>
              <Input value={d.name} onChange={(e) => setD({ ...d, name: e.target.value })} />
            </div>
            <div className="grid gap-1.5">
              <Label className="text-xs">Analyst coverage</Label>
              <Input value={d.coverage} onChange={(e) => setD({ ...d, coverage: e.target.value })} aria-describedby="coverage-hint" />
              <p id="coverage-hint" className="text-[11px] text-muted-foreground">Hours × days, e.g. 24x7 or 8x5</p>
            </div>
            <div className="grid gap-1.5 sm:col-span-2">
              <Label className="text-xs">Tagline</Label>
              <Input value={d.tagline} onChange={(e) => setD({ ...d, tagline: e.target.value })} />
            </div>
            <div className="grid gap-1.5">
              <Label className="text-xs">Key</Label>
              <Input value={d.key} onChange={(e) => setD({ ...d, key: e.target.value })} disabled={!!plan} className="font-mono" />
              <p className="text-[11px] text-muted-foreground">{plan ? "Fixed once created" : "Optional; derived from the name"}</p>
            </div>
          </div>

          <div>
            <p className="mb-2 text-sm font-medium">SLA targets (minutes) <span className="font-normal text-muted-foreground">· empty = no target for that severity</span></p>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[30rem] text-sm">
                <thead>
                  <tr className="text-left text-xs text-muted-foreground">
                    <th className="py-1 pr-2 font-medium" />
                    {SEVERITIES.map((sev) => <th key={sev} className="px-1 py-1 font-medium">{sev.toLowerCase()}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {(["ack", "contain"] as const).map((row) => (
                    <tr key={row}>
                      <td className="py-1 pr-2 text-xs text-muted-foreground">{row === "ack" ? "Acknowledge within" : "Contain within"}</td>
                      {SEVERITIES.map((sev) => (
                        <td key={sev} className="px-1 py-1">
                          <Input value={d[row][sev]} onChange={(e) => setD({ ...d, [row]: { ...d[row], [sev]: e.target.value } })} inputMode="numeric" className="h-8 tabular" aria-label={`${row} ${sev}`} />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-4">
            {field("Price per endpoint / month (USD)", d.pricePerEndpoint, (v) => setD({ ...d, pricePerEndpoint: v }))}
            {field("Your cost per endpoint / month", d.costPerEndpoint, (v) => setD({ ...d, costPerEndpoint: v }), "For margin; internal")}
            {field("Onboarding minimum (USD)", d.onboardingMinimum, (v) => setD({ ...d, onboardingMinimum: v }), "Empty = no minimum")}
            {field("IR retainer hours / year", d.irRetainerHours, (v) => setD({ ...d, irRetainerHours: v }))}
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            <div className="grid gap-1.5 sm:col-span-2">
              <Label className="text-xs">Default AI autonomy for new clients</Label>
              <NativeSelect value={d.defaultAutonomyCap} onChange={(e) => setD({ ...d, defaultAutonomyCap: e.target.value as AiAutonomy })}>
                {AUTONOMY_ORDER.map((a) => <option key={a} value={a}>{AUTONOMY_LABEL[a]}</option>)}
              </NativeSelect>
            </div>
            {field("Display order", d.sortOrder, (v) => setD({ ...d, sortOrder: v }))}
          </div>

          <div>
            <p className="mb-2 text-sm font-medium">What&apos;s included <span className="font-normal text-muted-foreground">· optional detail shown on quotes and the comparison</span></p>
            <div className="grid gap-2 sm:grid-cols-2">
              {PLAN_FEATURES.map((f) => (
                <div key={f} className="flex items-center gap-2 rounded-md border p-2">
                  <Switch checked={d.features[f].on} onCheckedChange={(on) => setD({ ...d, features: { ...d.features, [f]: { ...d.features[f], on } } })} aria-label={PLAN_FEATURE_LABEL[f]} />
                  <span className="min-w-0 flex-1 text-xs">{PLAN_FEATURE_LABEL[f]}</span>
                  {d.features[f].on && <Input value={d.features[f].text} onChange={(e) => setD({ ...d, features: { ...d.features, [f]: { on: true, text: e.target.value } } })} className="h-7 w-36 text-xs" aria-label={`${PLAN_FEATURE_LABEL[f]} detail`} />}
                </div>
              ))}
            </div>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={d.active} onCheckedChange={(active) => setD({ ...d, active })} /> Offered to new clients
          </label>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => save.mutate()} disabled={save.isPending || !d.name.trim() || !d.coverage.trim()}>
            {save.isPending && <Loader2 className="animate-spin" />} Save plan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function PlansEditor({ plans, tenantCounts, canEdit }: { plans: ServicePlan[]; tenantCounts: Record<string, number>; canEdit: boolean }) {
  const router = useRouter();
  const [editing, setEditing] = React.useState<ServicePlan | "new" | null>(null);
  const remove = useMutation({
    mutationFn: (id: string) => deletePlanAction(id),
    onSuccess: (r) => {
      toast.success(r.retired ? "Plan retired — clients on it keep their SLA" : "Plan deleted");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  return (
    <div className="flex flex-col gap-3">
      {plans.length === 0 ? (
        <EmptyState icon={Layers} title="No service plans yet" description="Define the plans you sell — SLA targets, price per endpoint and what's included. Client SLAs and quotes use them." />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[40rem] text-sm">
            <thead>
              <tr className="border-b text-left text-xs text-muted-foreground">
                <th className="py-2 pr-3 font-medium">Plan</th>
                <th className="px-2 py-2 font-medium">Coverage</th>
                <th className="px-2 py-2 font-medium">Ack critical / high</th>
                <th className="px-2 py-2 text-right font-medium">Per endpoint</th>
                <th className="px-2 py-2 text-right font-medium">Clients</th>
                <th />
              </tr>
            </thead>
            <tbody className="divide-y">
              {plans.map((p) => (
                <tr key={p.id}>
                  <td className="py-2 pr-3">
                    <p className="font-medium">{p.name} {!p.active && <Badge variant="soft">retired</Badge>}</p>
                    <p className="text-[11px] text-muted-foreground">{p.tagline ?? p.key}</p>
                  </td>
                  <td className="px-2 py-2 text-xs">{p.coverage}</td>
                  <td className="px-2 py-2 text-xs tabular">{formatMinutes(p.ackMinutes.CRITICAL)} / {formatMinutes(p.ackMinutes.HIGH)}</td>
                  <td className="px-2 py-2 text-right tabular">{p.pricePerEndpoint == null ? <Badge variant="warning">not set</Badge> : `$${p.pricePerEndpoint.toFixed(2)}`}</td>
                  <td className="px-2 py-2 text-right tabular">{tenantCounts[p.id] ?? 0}</td>
                  <td className="py-2 text-right">
                    {canEdit && (
                      <div className="flex justify-end gap-1">
                        <Button size="icon" variant="ghost" className="size-7" aria-label={`Edit ${p.name}`} onClick={() => setEditing(p)}><Pencil /></Button>
                        <Button size="icon" variant="ghost" className="size-7" aria-label={`Delete ${p.name}`} disabled={remove.isPending} onClick={() => { if (confirm(tenantCounts[p.id] ? `${p.name} has clients; it will be retired instead of deleted.` : `Delete ${p.name}?`)) remove.mutate(p.id); }}><Trash2 /></Button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {canEdit && (
        <Button size="sm" variant="outline" className="self-start" onClick={() => setEditing("new")}>
          <Plus /> New plan
        </Button>
      )}
      {editing && <PlanDialog key={editing === "new" ? "new" : editing.id} plan={editing === "new" ? undefined : editing} open onOpenChange={(v) => !v && setEditing(null)} />}
    </div>
  );
}
