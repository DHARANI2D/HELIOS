"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Ban, Check, FileSignature, Loader2, Plus, Receipt, RefreshCw, Save, Send, X } from "lucide-react";
import { toast } from "sonner";

import { contractFromQuoteAction, convertPilotAction, draftDueInvoicesAction, endContractAction, issueInvoiceAction, markPaidAction, pilotNotConvertedAction, saveBillingProfileAction, saveBillingSettingsAction, saveContractAction, sendContractAction, signContractAction, voidInvoiceAction } from "@/app/(app)/billing/actions";
import { CYCLE_MONTHS, PILOT_METRICS, type Criterion, type PilotMetric } from "@/lib/billing/terms";
import { GST_STATES } from "@/lib/billing/gst";
import type { BillingSettings } from "@/lib/settings";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";
import { unwrap } from "@/lib/action-result";

const onError = (e: Error) => toast.error(e.message);
const today = () => new Date().toISOString().slice(0, 10);

export interface ContractFormValue {
  kind: "PILOT" | "SUBSCRIPTION";
  currency: string;
  planName: string;
  monthlyFee: number;
  endpointsCommitted: number;
  overagePerEndpoint: number;
  oneTimeFee: number;
  billingCycle: keyof typeof CYCLE_MONTHS;
  paymentTermsDays: number;
  startsAt: string;
  months: number;
  autoRenew: boolean;
  noticeDays: number;
  liabilityCapMonths: number;
  successCriteria: Criterion[];
}

export const NEW_CONTRACT: ContractFormValue = { kind: "SUBSCRIPTION", currency: "INR", planName: "", monthlyFee: 0, endpointsCommitted: 0, overagePerEndpoint: 0, oneTimeFee: 0, billingCycle: "monthly", paymentTermsDays: 30, startsAt: "", months: 12, autoRenew: false, noticeDays: 30, liabilityCapMonths: 12, successCriteria: [] };
const PILOT_DEFAULTS: Partial<ContractFormValue> = { kind: "PILOT", months: 1, monthlyFee: 0, billingCycle: "monthly", noticeDays: 0, autoRenew: false, successCriteria: [{ metric: "mtta_minutes", target: 15 }, { metric: "ai_agreement_pct", target: 90 }, { metric: "critical_false_containments", target: 0 }, { metric: "sources_live_pct", target: 100 }] };

export function ContractForm({ tenants, initial, contractId, tenantId: fixedTenant }: { tenants: Array<{ id: string; name: string }>; initial?: ContractFormValue; contractId?: string; tenantId?: string }) {
  const router = useRouter();
  const [v, setV] = React.useState<ContractFormValue>(initial ?? { ...NEW_CONTRACT, startsAt: today() });
  const [tenantId, setTenantId] = React.useState(fixedTenant ?? tenants[0]?.id ?? "");
  const set = <K extends keyof ContractFormValue>(k: K, x: ContractFormValue[K]) => setV((p) => ({ ...p, [k]: x }));
  const num = (k: "monthlyFee" | "endpointsCommitted" | "overagePerEndpoint" | "oneTimeFee" | "paymentTermsDays" | "months" | "noticeDays" | "liabilityCapMonths") => (e: React.ChangeEvent<HTMLInputElement>) => set(k, Number(e.target.value) || 0);
  const save = useMutation({
    mutationFn: () => unwrap(saveContractAction(contractId ?? null, tenantId, v)),
    onSuccess: (id) => { toast.success(contractId ? "Draft saved" : "Draft created"); if (!contractId) router.push(`/billing/contracts/${id}`); else router.refresh(); },
    onError,
  });
  const field = (id: string, label: string, el: React.ReactNode) => <div className="grid gap-1"><Label htmlFor={id} className="text-xs">{label}</Label>{el}</div>;
  return (
    <div className="flex flex-col gap-3">
      <div className="grid gap-2 sm:grid-cols-4">
        {!contractId && field("ct-kind", "Kind", <NativeSelect id="ct-kind" className="h-8 text-xs" value={v.kind} onChange={(e) => setV((p) => (e.target.value === "PILOT" ? { ...p, ...PILOT_DEFAULTS } : { ...p, kind: "SUBSCRIPTION", months: 12 }))}><option value="SUBSCRIPTION">Subscription</option><option value="PILOT">Pilot</option></NativeSelect>)}
        {!fixedTenant && field("ct-client", "Client", <NativeSelect id="ct-client" className="h-8 text-xs" value={tenantId} onChange={(e) => setTenantId(e.target.value)}>{tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</NativeSelect>)}
        {field("ct-plan", "Plan or service name", <Input id="ct-plan" className="h-8 text-xs" value={v.planName} onChange={(e) => set("planName", e.target.value)} />)}
        {field("ct-cur", "Currency", <Input id="ct-cur" className="h-8 text-xs uppercase" maxLength={3} value={v.currency} onChange={(e) => set("currency", e.target.value.toUpperCase())} />)}
        {field("ct-fee", "Monthly fee", <Input id="ct-fee" type="number" min={0} className="h-8 text-xs" value={v.monthlyFee} onChange={num("monthlyFee")} />)}
        {field("ct-ep", "Endpoints committed", <Input id="ct-ep" type="number" min={0} className="h-8 text-xs" value={v.endpointsCommitted} onChange={num("endpointsCommitted")} />)}
        {field("ct-over", "Per endpoint above, per month", <Input id="ct-over" type="number" min={0} className="h-8 text-xs" value={v.overagePerEndpoint} onChange={num("overagePerEndpoint")} />)}
        {field("ct-once", "One-time fee", <Input id="ct-once" type="number" min={0} className="h-8 text-xs" value={v.oneTimeFee} onChange={num("oneTimeFee")} />)}
        {field("ct-start", "Starts", <Input id="ct-start" type="date" className="h-8 text-xs" value={v.startsAt} onChange={(e) => set("startsAt", e.target.value)} />)}
        {field("ct-months", "Term (months)", <Input id="ct-months" type="number" min={1} max={60} className="h-8 text-xs" value={v.months} onChange={num("months")} />)}
        {field("ct-cycle", "Invoiced", <NativeSelect id="ct-cycle" className="h-8 text-xs" value={v.billingCycle} onChange={(e) => set("billingCycle", e.target.value as ContractFormValue["billingCycle"])}><option value="monthly">Monthly</option><option value="quarterly">Quarterly</option><option value="annual">Annually</option></NativeSelect>)}
        {field("ct-pay", "Payment within (days)", <Input id="ct-pay" type="number" min={0} className="h-8 text-xs" value={v.paymentTermsDays} onChange={num("paymentTermsDays")} />)}
        {field("ct-notice", "Notice (days)", <Input id="ct-notice" type="number" min={0} className="h-8 text-xs" value={v.noticeDays} onChange={num("noticeDays")} />)}
        {field("ct-cap", "Liability cap (months of fees)", <Input id="ct-cap" type="number" min={0} className="h-8 text-xs" value={v.liabilityCapMonths} onChange={num("liabilityCapMonths")} />)}
        <label className="flex items-center gap-1.5 pt-5 text-xs"><input type="checkbox" checked={v.autoRenew} disabled={v.kind === "PILOT"} onChange={(e) => set("autoRenew", e.target.checked)} /> Renews for the same term</label>
      </div>
      {v.kind === "PILOT" && (
        <div className="rounded-md border p-3">
          <p className="mb-2 text-xs text-muted-foreground">Success criteria, measured from HELIOS&apos;s records over the pilot:</p>
          <div className="flex flex-col gap-1.5">
            {v.successCriteria.map((c, i) => (
              <div key={i} className="flex items-center gap-2">
                <NativeSelect aria-label="Measure" className="h-8 flex-1 text-xs" value={c.metric} onChange={(e) => set("successCriteria", v.successCriteria.map((x, j) => (j === i ? { ...x, metric: e.target.value as PilotMetric } : x)))}>
                  {(Object.keys(PILOT_METRICS) as PilotMetric[]).map((m) => <option key={m} value={m}>{PILOT_METRICS[m].label}</option>)}
                </NativeSelect>
                <span className="text-xs text-muted-foreground">{PILOT_METRICS[c.metric].better === "lower" ? "at most" : "at least"}</span>
                <Input aria-label="Target" type="number" min={0} className="h-8 w-24 text-xs" value={c.target} onChange={(e) => set("successCriteria", v.successCriteria.map((x, j) => (j === i ? { ...x, target: Number(e.target.value) || 0 } : x)))} />
                <Button size="icon" variant="ghost" className="size-7" aria-label="Remove criterion" onClick={() => set("successCriteria", v.successCriteria.filter((_, j) => j !== i))}><X className="size-3.5" /></Button>
              </div>
            ))}
            <div><Button size="sm" variant="ghost" onClick={() => set("successCriteria", [...v.successCriteria, { metric: "cases_handled", target: 1 }])}><Plus /> Add a criterion</Button></div>
          </div>
        </div>
      )}
      <div><Button size="sm" disabled={save.isPending || !tenantId || !v.startsAt} onClick={() => save.mutate()}>{save.isPending ? <Loader2 className="animate-spin" /> : <Save />} {contractId ? "Save draft" : "Create draft"}</Button></div>
    </div>
  );
}

export function FromQuoteForm({ quotes, tenants }: { quotes: Array<{ id: string; reference: string; clientName: string; tenantId: string | null }>; tenants: Array<{ id: string; name: string }> }) {
  const router = useRouter();
  const [quoteId, setQuoteId] = React.useState(quotes[0]?.id ?? "");
  const quote = quotes.find((q) => q.id === quoteId);
  const [tenantId, setTenantId] = React.useState("");
  const [startsAt, setStartsAt] = React.useState(today());
  const go = useMutation({ mutationFn: () => unwrap(contractFromQuoteAction(quoteId, tenantId || quote?.tenantId || null, startsAt)), onSuccess: (id) => router.push(`/billing/contracts/${id}`), onError });
  if (!quotes.length) return <p className="text-xs text-muted-foreground">No sent or accepted quotes to start from.</p>;
  return (
    <div className="grid gap-2 sm:grid-cols-[1fr_1fr_10rem_auto] sm:items-end">
      <div className="grid gap-1"><Label htmlFor="fq-quote" className="text-xs">Quote</Label><NativeSelect id="fq-quote" className="h-8 text-xs" value={quoteId} onChange={(e) => setQuoteId(e.target.value)}>{quotes.map((q) => <option key={q.id} value={q.id}>{q.reference} · {q.clientName}</option>)}</NativeSelect></div>
      <div className="grid gap-1"><Label htmlFor="fq-client" className="text-xs">For client</Label><NativeSelect id="fq-client" className="h-8 text-xs" value={tenantId || quote?.tenantId || ""} onChange={(e) => setTenantId(e.target.value)}><option value="">Choose…</option>{tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</NativeSelect></div>
      <div className="grid gap-1"><Label htmlFor="fq-start" className="text-xs">Starts</Label><Input id="fq-start" type="date" className="h-8 text-xs" value={startsAt} onChange={(e) => setStartsAt(e.target.value)} /></div>
      <Button size="sm" variant="outline" disabled={go.isPending || !quoteId || !(tenantId || quote?.tenantId)} onClick={() => go.mutate()}>{go.isPending ? <Loader2 className="animate-spin" /> : <FileSignature />} Draft from quote</Button>
    </div>
  );
}

export function ContractActions({ id, status, kind, canManage, canSignAsClient, converted, outcome }: { id: string; status: string; kind: string; canManage: boolean; canSignAsClient: boolean; converted: string | null; outcome: string | null }) {
  const router = useRouter();
  const [name, setName] = React.useState("");
  const [title, setTitle] = React.useState("");
  const [via, setVia] = React.useState(canSignAsClient ? "in_app" : "e_sign");
  const refresh = (msg: string) => () => { toast.success(msg); router.refresh(); };
  const send = useMutation({ mutationFn: () => unwrap(sendContractAction(id)), onSuccess: refresh("Sent to the client to sign"), onError });
  const sign = useMutation({ mutationFn: () => unwrap(signContractAction(id, { name, title, via })), onSuccess: refresh("Signed"), onError });
  const end = useMutation({
    mutationFn: async (terminate: boolean) => {
      const reason = prompt(terminate ? "Why is it terminated?" : "Why does it end now?");
      if (!reason) throw new Error("Say why");
      return unwrap(endContractAction(id, reason, terminate));
    },
    onSuccess: refresh("Done"),
    onError,
  });
  const convert = useMutation({ mutationFn: () => unwrap(convertPilotAction(id)), onSuccess: (sub) => router.push(`/billing/contracts/${sub}`), onError });
  const notConverted = useMutation({ mutationFn: () => unwrap(pilotNotConvertedAction(id)), onSuccess: refresh("Recorded"), onError });
  return (
    <div className="flex flex-col gap-3">
      {status === "SENT" && (canSignAsClient || canManage) && (
        <div className="grid gap-2 rounded-md border p-3 sm:grid-cols-[1fr_1fr_9rem_auto] sm:items-end">
          <div className="grid gap-1"><Label htmlFor="sg-name" className="text-xs">{canSignAsClient ? "Your name" : "Signed by"}</Label><Input id="sg-name" className="h-8 text-xs" value={name} onChange={(e) => setName(e.target.value)} /></div>
          <div className="grid gap-1"><Label htmlFor="sg-title" className="text-xs">Title</Label><Input id="sg-title" className="h-8 text-xs" value={title} onChange={(e) => setTitle(e.target.value)} /></div>
          {!canSignAsClient ? (
            <div className="grid gap-1"><Label htmlFor="sg-via" className="text-xs">How</Label><NativeSelect id="sg-via" className="h-8 text-xs" value={via} onChange={(e) => setVia(e.target.value)}><option value="e_sign">E-signature</option><option value="paper">On paper</option></NativeSelect></div>
          ) : <span />}
          <Button size="sm" disabled={sign.isPending || name.trim().length < 2} onClick={() => sign.mutate()}>{sign.isPending ? <Loader2 className="animate-spin" /> : <FileSignature />} {canSignAsClient ? "Sign" : "Record signature"}</Button>
          {canSignAsClient && <p className="text-xs text-muted-foreground sm:col-span-4">Signing in HELIOS records your name, title, the time and your account in the audit log.</p>}
        </div>
      )}
      {canManage && (
        <div className="flex flex-wrap gap-2">
          {status === "DRAFT" && <Button size="sm" disabled={send.isPending} onClick={() => send.mutate()}>{send.isPending ? <Loader2 className="animate-spin" /> : <Send />} Send to sign</Button>}
          {kind === "PILOT" && ["ACTIVE", "ENDED"].includes(status) && !converted && !outcome && (
            <>
              <Button size="sm" disabled={convert.isPending} onClick={() => convert.mutate()}>{convert.isPending ? <Loader2 className="animate-spin" /> : <RefreshCw />} Convert to a subscription</Button>
              <Button size="sm" variant="outline" disabled={notConverted.isPending} onClick={() => notConverted.mutate()}>Won&apos;t continue</Button>
            </>
          )}
          {["DRAFT", "SENT", "ACTIVE"].includes(status) && <Button size="sm" variant="outline" disabled={end.isPending} onClick={() => end.mutate(false)}>End now</Button>}
          {status === "ACTIVE" && <Button size="sm" variant="ghost" className="text-destructive" disabled={end.isPending} onClick={() => end.mutate(true)}><Ban /> Terminate</Button>}
        </div>
      )}
    </div>
  );
}

export interface ProfileValue {
  legalName: string;
  gstin: string;
  address: string;
  state: string;
  country: string;
  email: string;
  poNumber: string;
}

export function BillingProfileForm({ tenantId, contractId, value }: { tenantId: string; contractId?: string; value: ProfileValue }) {
  const router = useRouter();
  const [v, setV] = React.useState(value);
  const set = (k: keyof ProfileValue) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => setV((p) => ({ ...p, [k]: e.target.value }));
  const save = useMutation({ mutationFn: () => unwrap(saveBillingProfileAction(tenantId, v, contractId)), onSuccess: () => { toast.success("Billing details saved"); router.refresh(); }, onError });
  return (
    <div className="grid gap-2 sm:grid-cols-2">
      <div className="grid gap-1"><Label htmlFor="bp-name" className="text-xs">Legal name</Label><Input id="bp-name" className="h-8 text-xs" value={v.legalName} onChange={set("legalName")} /></div>
      <div className="grid gap-1"><Label htmlFor="bp-gstin" className="text-xs">GSTIN (blank if unregistered)</Label><Input id="bp-gstin" className="h-8 font-mono text-xs uppercase" maxLength={15} value={v.gstin} onChange={set("gstin")} /></div>
      <div className="grid gap-1 sm:col-span-2"><Label htmlFor="bp-addr" className="text-xs">Billing address</Label><Textarea id="bp-addr" className="min-h-14 text-xs" value={v.address} onChange={set("address")} /></div>
      <div className="grid gap-1"><Label htmlFor="bp-country" className="text-xs">Country</Label><Input id="bp-country" className="h-8 text-xs" value={v.country} onChange={set("country")} /></div>
      <div className="grid gap-1">
        <Label htmlFor="bp-state" className="text-xs">State (the place of supply without a GSTIN)</Label>
        <NativeSelect id="bp-state" className="h-8 text-xs" value={v.state} onChange={set("state")}><option value="">—</option>{Object.entries(GST_STATES).map(([code, name]) => <option key={code} value={code}>{name} ({code})</option>)}</NativeSelect>
      </div>
      <div className="grid gap-1"><Label htmlFor="bp-email" className="text-xs">Accounts email</Label><Input id="bp-email" type="email" className="h-8 text-xs" value={v.email} onChange={set("email")} /></div>
      <div className="grid gap-1"><Label htmlFor="bp-po" className="text-xs">Purchase order</Label><Input id="bp-po" className="h-8 text-xs" value={v.poNumber} onChange={set("poNumber")} /></div>
      <div className="sm:col-span-2"><Button size="sm" variant="outline" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save billing details</Button></div>
    </div>
  );
}

export function InvoiceActions({ id, status }: { id: string; status: string }) {
  const router = useRouter();
  const issue = useMutation({ mutationFn: () => unwrap(issueInvoiceAction(id)), onSuccess: (n) => { toast.success(`Issued as ${n}`); router.refresh(); }, onError });
  const paid = useMutation({
    mutationFn: async () => {
      const ref = prompt("Payment reference (UTR, cheque number…)") ?? "";
      const on = prompt("Paid on (YYYY-MM-DD)", today());
      if (!on) throw new Error("When was it paid?");
      return unwrap(markPaidAction(id, ref, on));
    },
    onSuccess: () => { toast.success("Marked paid"); router.refresh(); },
    onError,
  });
  const voidIt = useMutation({
    mutationFn: async () => {
      if (status === "DRAFT") {
        if (!confirm("Discard this draft?")) throw new Error("Kept");
        return unwrap(voidInvoiceAction(id, ""));
      }
      const reason = prompt("Why is it voided? (It keeps its number.)");
      if (!reason) throw new Error("Say why");
      return unwrap(voidInvoiceAction(id, reason));
    },
    onSuccess: (r) => { toast.success(r === "discarded" ? "Draft discarded" : "Voided"); router.refresh(); },
    onError,
  });
  return (
    <div className="flex justify-end gap-1">
      {status === "DRAFT" && <Button size="sm" className="h-7 text-xs" disabled={issue.isPending} onClick={() => issue.mutate()}>{issue.isPending ? <Loader2 className="animate-spin" /> : <Receipt />} Issue</Button>}
      {status === "ISSUED" && <Button size="sm" variant="outline" className="h-7 text-xs" disabled={paid.isPending} onClick={() => paid.mutate()}><Check /> Paid</Button>}
      {(status === "DRAFT" || status === "ISSUED") && <Button size="sm" variant="ghost" className="h-7 text-xs" disabled={voidIt.isPending} onClick={() => voidIt.mutate()}>{status === "DRAFT" ? "Discard" : "Void"}</Button>}
    </div>
  );
}

export function DraftDueInvoices() {
  const router = useRouter();
  const go = useMutation({ mutationFn: () => unwrap(draftDueInvoicesAction()), onSuccess: (n) => { toast.success(n ? `${n} drafted` : "Nothing due"); router.refresh(); }, onError });
  return <Button size="sm" variant="outline" disabled={go.isPending} onClick={() => go.mutate()}>{go.isPending ? <Loader2 className="animate-spin" /> : <RefreshCw />} Draft what&apos;s due</Button>;
}

export function BillingSettingsForm({ value }: { value: BillingSettings }) {
  const router = useRouter();
  const [v, setV] = React.useState(value);
  const save = useMutation({ mutationFn: () => unwrap(saveBillingSettingsAction(v)), onSuccess: () => { toast.success("Saved"); router.refresh(); }, onError });
  return (
    <div className="grid gap-3 sm:grid-cols-4">
      <div className="grid gap-1"><Label htmlFor="bs-prefix" className="text-xs">Invoice number prefix</Label><Input id="bs-prefix" className="h-8 text-xs" maxLength={5} value={v.invoicePrefix} onChange={(e) => setV({ ...v, invoicePrefix: e.target.value })} /></div>
      <div className="grid gap-1"><Label htmlFor="bs-gst" className="text-xs">GST rate (%)</Label><Input id="bs-gst" type="number" min={0} max={40} className="h-8 text-xs" value={v.gstRatePct} onChange={(e) => setV({ ...v, gstRatePct: Number(e.target.value) || 0 })} /></div>
      <div className="grid gap-1"><Label htmlFor="bs-sac" className="text-xs">SAC code</Label><Input id="bs-sac" className="h-8 font-mono text-xs" maxLength={6} value={v.sac} onChange={(e) => setV({ ...v, sac: e.target.value })} /></div>
      <div className="grid gap-1"><Label htmlFor="bs-days" className="text-xs">Default payment days</Label><Input id="bs-days" type="number" min={0} max={120} className="h-8 text-xs" value={v.paymentTermsDays} onChange={(e) => setV({ ...v, paymentTermsDays: Number(e.target.value) || 0 })} /></div>
      <div className="grid gap-1 sm:col-span-2"><Label htmlFor="bs-pay" className="text-xs">Payment details on invoices (bank, UPI)</Label><Textarea id="bs-pay" className="min-h-16 text-xs" value={v.paymentDetails} onChange={(e) => setV({ ...v, paymentDetails: e.target.value })} /></div>
      <div className="grid gap-1 sm:col-span-2"><Label htmlFor="bs-dpa" className="text-xs">DPA reference (the data processing agreement under the DPDP Act)</Label><Input id="bs-dpa" className="h-8 text-xs" value={v.dpaReference} onChange={(e) => setV({ ...v, dpaReference: e.target.value })} /></div>
      <div className="grid gap-1 sm:col-span-4"><Label htmlFor="bs-terms" className="text-xs">Terms of service printed on contracts (your counsel&apos;s text; a contract can&apos;t be sent without it)</Label><Textarea id="bs-terms" className="min-h-32 text-xs" value={v.contractTerms} onChange={(e) => setV({ ...v, contractTerms: e.target.value })} /></div>
      <div className="sm:col-span-4"><Button size="sm" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save</Button></div>
    </div>
  );
}
