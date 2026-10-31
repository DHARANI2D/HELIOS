"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Download, FlaskConical, Loader2, Plus, Send, Trash2, Upload, X } from "lucide-react";
import { toast } from "sonner";

import {
  addAllowlistEntryAction,
  discardRulebookDraftAction,
  dryRunRulebookAction,
  exportRulebookYamlAction,
  importRulebookYamlAction,
  removeAllowlistEntryAction,
  submitRulebookAction,
} from "@/app/(app)/rulebook/actions";
import type { DryRunResult } from "@/lib/rulebook/dry-run";
import type { Outcome } from "@/lib/rulebook/evaluate";
import { RULED_ACTION_LABEL, type Rulebook } from "@/lib/rulebook/schema";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";
import { unwrap } from "@/lib/action-result";

function useAct<T, R = unknown>(fn: (v: T) => Promise<R>, done: (r: R) => string | null) {
  const router = useRouter();
  return useMutation({
    mutationFn: fn,
    onSuccess: (r) => {
      const msg = done(r);
      if (msg) toast.success(msg);
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
}

// ---------------------------------------------------------------- draft & sign

export function DraftControls({ tenantId, status, version, canEdit }: { tenantId: string; status: "DRAFT" | "AWAITING_SIGNATURE"; version: number; canEdit: boolean }) {
  const submit = useAct(() => unwrap(submitRulebookAction(tenantId)), (r) => `Sent for approval: it takes effect once the client signs it${r.notified ? ` (${r.notified} admin${r.notified === 1 ? "" : "s"} told)` : " (the client has no admin account yet)"} and HELIOS approves it`);
  const discard = useAct(() => unwrap(discardRulebookDraftAction(tenantId)), () => "Draft discarded");
  if (!canEdit) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {status === "DRAFT" && (
        <Button size="sm" onClick={() => submit.mutate(undefined)} disabled={submit.isPending}>
          {submit.isPending ? <Loader2 className="animate-spin" /> : <Send />} Send v{version} for approval
        </Button>
      )}
      <Button size="sm" variant="outline" onClick={() => discard.mutate(undefined)} disabled={discard.isPending}>
        <Trash2 /> Discard draft
      </Button>
    </div>
  );
}

// ---------------------------------------------------------------- dry run

const OUTCOME_LABEL: Record<Outcome, string> = { EXECUTED: "Automatic", PENDING_APPROVAL: "Held for approval", SUGGESTED: "Suggestion only", BLOCKED: "Blocked" };
const OUTCOME_VARIANT: Record<Outcome, "success" | "warning" | "outline" | "destructive"> = { EXECUTED: "success", PENDING_APPROVAL: "warning", SUGGESTED: "outline", BLOCKED: "destructive" };
const ORDER: Outcome[] = ["EXECUTED", "PENDING_APPROVAL", "SUGGESTED", "BLOCKED"];

export function DryRunPanel({ tenantId, book, label }: { tenantId: string; book: Rulebook; label: string }) {
  const run = useMutation({ mutationFn: () => unwrap(dryRunRulebookAction(tenantId, book)), onError: (err) => toast.error(err instanceof Error ? err.message : "Dry run failed") });
  const r = run.data as DryRunResult | undefined;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" onClick={() => run.mutate()} disabled={run.isPending}>
          {run.isPending ? <Loader2 className="animate-spin" /> : <FlaskConical />} Dry-run {label}
        </Button>
        <p className="text-xs text-muted-foreground">Replays the last 30 days of AI containment proposals under these rules and probes each action now. Nothing is executed.</p>
      </div>
      {r && (
        <>
          <div className="rounded-lg border p-3">
            <p className="text-sm font-medium">Last {r.days} days: {r.total} AI proposal{r.total === 1 ? "" : "s"}</p>
            {r.total === 0 ? (
              <p className="text-xs text-muted-foreground">No AI containment proposals for this client yet; the probes below show how the rules will behave.</p>
            ) : (
              <table className="mt-2 w-full max-w-md text-xs">
                <thead className="text-left text-muted-foreground"><tr><th>Outcome</th><th className="text-right">At the time</th><th className="text-right">Under these rules</th></tr></thead>
                <tbody>
                  {ORDER.map((o) => (
                    <tr key={o} className="border-t"><td className="py-1">{OUTCOME_LABEL[o]}</td><td className="text-right">{r.then[o]}</td><td className={cn("text-right", r.now[o] !== r.then[o] && "font-semibold")}>{r.now[o]}</td></tr>
                  ))}
                </tbody>
              </table>
            )}
            {r.changes.length > 0 && (
              <details className="mt-2">
                <summary className="cursor-pointer text-xs">{r.changes.length} decision{r.changes.length === 1 ? "" : "s"} would change</summary>
                <ul className="mt-1 flex flex-col gap-1 text-xs">
                  {r.changes.map((c) => (
                    <li key={c.id}>
                      <a className="underline-offset-2 hover:underline" href={`/cases/${c.caseId}`}>{c.caseTitle}</a>: {RULED_ACTION_LABEL[c.action as keyof typeof RULED_ACTION_LABEL] ?? c.action} {c.target && <code className="font-mono">{c.target}</code>} ({c.severity.toLowerCase()}) — {OUTCOME_LABEL[c.then]} → <span className="font-medium">{OUTCOME_LABEL[c.now]}</span>
                      <span className="text-muted-foreground"> · {c.reason}</span>
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </div>
          <div className="rounded-lg border p-3">
            <p className="text-sm font-medium">A confident AI proposal right now</p>
            <p className="text-xs text-muted-foreground">95% confidence, target in the evidence, ordinary asset — with today&apos;s plan, consent, agent profile and these rules.</p>
            <div className="mt-2 overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="text-left text-muted-foreground"><tr><th className="py-1">Action</th>{r.probes[0]?.outcomes.map((o) => <th key={o.severity}>{o.severity.toLowerCase()}</th>)}</tr></thead>
                <tbody>
                  {r.probes.map((p) => (
                    <tr key={p.action} className="border-t">
                      <td className="py-1 pr-2">{RULED_ACTION_LABEL[p.action]}</td>
                      {p.outcomes.map((o) => (
                        <td key={o.severity} className="pr-2" title={o.reason}><Badge variant={OUTCOME_VARIANT[o.outcome]}>{OUTCOME_LABEL[o.outcome]}</Badge></td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <ul className="mt-2 flex flex-col gap-0.5 text-[11px] text-muted-foreground">
              {[...new Set(r.probes.flatMap((p) => p.outcomes.filter((o) => o.outcome !== "EXECUTED").map((o) => o.reason)))].slice(0, 8).map((reason) => (
                <li key={reason}>· {reason}</li>
              ))}
            </ul>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <div className="rounded-lg border p-3 text-xs">
              <p className="text-sm font-medium">Assets ({r.assets.total} in the inventory)</p>
              <p className="mt-1"><span className="font-medium">Never isolated:</span> {r.assets.neverIsolate.length ? r.assets.neverIsolate.slice(0, 30).join(", ") + (r.assets.neverIsolate.length > 30 ? ` +${r.assets.neverIsolate.length - 30}` : "") : "none matched"}</p>
              <p className="mt-1"><span className="font-medium">Tier 1:</span> {r.assets.crownJewels.length ? r.assets.crownJewels.slice(0, 30).join(", ") + (r.assets.crownJewels.length > 30 ? ` +${r.assets.crownJewels.length - 30}` : "") : "none matched"}</p>
            </div>
            <div className="rounded-lg border p-3 text-xs">
              <p className="text-sm font-medium">Accounts ({r.accounts.seen} seen in 30 days)</p>
              <p className="mt-1"><span className="font-medium">Never disabled:</span> {r.accounts.protected.join(", ") || "none matched"}</p>
              <p className="mt-1"><span className="font-medium">VIP:</span> {r.accounts.vip.join(", ") || "none matched"}</p>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- allowlist

export interface AllowlistRow {
  id: string;
  kind: string;
  value: string;
  reason: string;
  owner: string;
  expiresAt: string | null;
  expired: boolean;
}

const KINDS = { ip: "IP address", host: "Host", user: "Account", domain: "Sender domain", sender: "Sender address", hash: "File hash", process: "Process" };

export function AllowlistPanel({ tenantId, rows, canEdit }: { tenantId: string; rows: AllowlistRow[]; canEdit: boolean }) {
  const [d, setD] = React.useState({ kind: "ip" as keyof typeof KINDS, value: "", reason: "", owner: "", expiresAt: "" });
  const add = useAct(() => unwrap(addAllowlistEntryAction(tenantId, { ...d, expiresAt: d.expiresAt || null })), () => {
    setD({ ...d, value: "", reason: "" });
    return "Sent for approval: it's allowlisted once the client and HELIOS approve it";
  });
  const remove = useAct((id: string) => unwrap(removeAllowlistEntryAction(tenantId, id)), () => "Removal sent for approval");
  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-muted-foreground">
        Activity the client vouches for: a vulnerability scanner, an admin tool, an expected job. Detections about an allowlisted host, IP or account don&apos;t open cases, and AI containment against them is only suggested. Every entry has an owner, a reason and ideally an expiry. Adding or removing one is a rule change: it takes effect once the client and HELIOS have both approved it.
      </p>
      {rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">Nothing allowlisted.</p>
      ) : (
        <table className="w-full text-xs">
          <thead className="text-left text-muted-foreground"><tr><th className="py-1">What</th><th>Value</th><th>Why</th><th>Owner</th><th>Until</th><th /></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className={cn("border-t", r.expired && "text-muted-foreground line-through")}>
                <td className="py-1">{KINDS[r.kind as keyof typeof KINDS] ?? r.kind}</td>
                <td className="font-mono">{r.value}</td>
                <td>{r.reason}</td>
                <td>{r.owner}</td>
                <td>{r.expiresAt ? r.expiresAt.slice(0, 10) : "no expiry"}</td>
                <td className="text-right">{canEdit && <Button size="icon" variant="ghost" className="size-7" onClick={() => remove.mutate(r.id)} aria-label="Remove"><X /></Button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {canEdit && (
        <div className="flex flex-wrap items-end gap-1.5 rounded-lg border p-2">
          <NativeSelect className="h-8 w-36 text-xs" value={d.kind} onChange={(e) => setD({ ...d, kind: e.target.value as keyof typeof KINDS })} aria-label="Kind">
            {Object.entries(KINDS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </NativeSelect>
          <Input className="h-8 w-44 font-mono text-xs" value={d.value} onChange={(e) => setD({ ...d, value: e.target.value })} placeholder="10.0.5.20" aria-label="Value" />
          <Input className="h-8 min-w-44 flex-1 text-xs" value={d.reason} onChange={(e) => setD({ ...d, reason: e.target.value })} placeholder="Why it's expected" aria-label="Reason" />
          <Input className="h-8 w-36 text-xs" value={d.owner} onChange={(e) => setD({ ...d, owner: e.target.value })} placeholder="Owner" aria-label="Owner" />
          <div className="grid gap-1">
            <Label htmlFor="al-exp" className="text-[11px] text-muted-foreground">Expires</Label>
            <Input id="al-exp" type="date" className="h-8 w-36 text-xs" value={d.expiresAt} onChange={(e) => setD({ ...d, expiresAt: e.target.value })} />
          </div>
          <Button size="sm" className="h-8" onClick={() => add.mutate(undefined)} disabled={add.isPending || !d.value || d.reason.length < 3 || d.owner.length < 2}>
            <Plus /> Add
          </Button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- policy as code

export function CodePanel({ tenantId, book, canEdit }: { tenantId: string; book: Rulebook; canEdit: boolean }) {
  const [yaml, setYaml] = React.useState("");
  const [reason, setReason] = React.useState("");
  const exp = useMutation({ mutationFn: () => unwrap(exportRulebookYamlAction(tenantId, book)), onSuccess: (text) => setYaml(text), onError: (err) => toast.error(err instanceof Error ? err.message : "Export failed") });
  const imp = useAct(() => unwrap(importRulebookYamlAction(tenantId, { yaml, reason })), (r) => `Imported as draft v${r?.version}`);
  const download = () => {
    const url = URL.createObjectURL(new Blob([yaml], { type: "application/yaml" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "rulebook.yaml";
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="flex flex-col gap-2">
      <p className="text-xs text-muted-foreground">The rulebook as YAML, for review in Git or bulk edits. Importing validates against the same schema as the editor and saves a draft; it still needs the client&apos;s signature.</p>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="outline" onClick={() => exp.mutate()} disabled={exp.isPending}><Download /> Show as YAML</Button>
        {yaml && <Button size="sm" variant="outline" onClick={download}><Download /> Download</Button>}
        {canEdit && (
          <label className="inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-md border px-3 text-xs">
            <Upload className="size-3.5" /> Load a file
            <input type="file" accept=".yaml,.yml,text/yaml" className="hidden" onChange={async (e) => { const f = e.target.files?.[0]; if (f) setYaml(await f.text()); }} />
          </label>
        )}
      </div>
      <Textarea className="min-h-72 font-mono text-xs" value={yaml} onChange={(e) => setYaml(e.target.value)} spellCheck={false} aria-label="Rulebook YAML" readOnly={!canEdit} />
      {canEdit && (
        <div className="flex flex-wrap gap-2">
          <Input className="h-8 min-w-64 flex-1 text-xs" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why (required)" aria-label="Reason for the import" />
          <Button size="sm" onClick={() => imp.mutate(undefined)} disabled={imp.isPending || !yaml.trim() || reason.trim().length < 3}>
            {imp.isPending ? <Loader2 className="animate-spin" /> : <Upload />} Import as draft
          </Button>
        </div>
      )}
    </div>
  );
}
