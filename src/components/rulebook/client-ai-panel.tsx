"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { KeyRound, Loader2, Plus, Radio, Save, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { deleteClientProviderAction, saveClientAiPolicyAction, saveClientProviderAction, saveMyModelPreferenceAction, testClientProviderAction } from "@/app/(app)/rulebook/ai-actions";
import type { Resolution } from "@/lib/ai/gateway";
import type { ProviderKind } from "@/lib/ai/catalog";

const KIND_DEFAULT_MODEL: Record<ProviderKind, string> = { anthropic: "claude-sonnet-5-5", bedrock: "anthropic.claude-sonnet-5-5", azure_openai: "gpt-4o", openai_compatible: "qwen2.5:14b" };
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { unwrap } from "@/lib/action-result";

export interface ProviderView {
  id: string;
  name: string;
  kind: string;
  model: string;
  isLocal: boolean;
  region: string | null;
  own: boolean;
  lastCheckOk: boolean | null;
  lastCheckMessage: string | null;
  // Why the client's rulebook doesn't allow it, or null.
  blocked: string | null;
}

interface Props {
  tenantId: string;
  canEdit: boolean;
  rulesText: string;
  providers: ProviderView[];
  agents: Array<{ key: string; name: string; resolution: Resolution }>;
  defaults: Record<string, string>;
  budget: number | null;
  spend: { spent: number; runs: number; clientKeyRuns: number };
  mine: Record<string, string> | null; // the viewer's own choices, when users may choose
}

const SOURCE: Record<Resolution["source"], string> = {
  user: "your choice",
  client: "client's choice",
  profile: "agent profile",
  platform: "platform default",
  environment: "environment key",
  builtin: "built-in engine",
};

function useAct<T, R>(fn: (v: T) => Promise<R>, msg: (r: R) => string) {
  const router = useRouter();
  return useMutation({ mutationFn: fn, onSuccess: (r) => { toast.success(msg(r)); router.refresh(); }, onError: (e) => toast.error(e instanceof Error ? e.message : "Failed") });
}

export function ClientAiPanel({ tenantId, canEdit, rulesText, providers, agents, defaults, budget, spend, mine }: Props) {
  const [choice, setChoice] = React.useState(defaults);
  const [limit, setLimit] = React.useState(budget ? String(budget) : "");
  const [adding, setAdding] = React.useState(false);
  const [d, setD] = React.useState({ name: "", kind: "anthropic" as ProviderKind, baseUrl: "", model: "claude-sonnet-5-5", apiKey: "", awsAccessKeyId: "", awsSecretAccessKey: "", isLocal: false, region: "" });
  const savePolicy = useAct(() => unwrap(saveClientAiPolicyAction(tenantId, { defaults: choice, monthlyBudgetUsd: limit ? Number(limit) : null })), () => "AI choices saved");
  const addProvider = useAct(() => unwrap(saveClientProviderAction(tenantId, { ...d, awsAccessKeyId: d.awsAccessKeyId || undefined, awsSecretAccessKey: d.awsSecretAccessKey || undefined, apiKey: d.apiKey || undefined })), () => {
    setAdding(false);
    setD({ ...d, name: "", apiKey: "", awsAccessKeyId: "", awsSecretAccessKey: "" });
    return "Provider added";
  });
  const remove = useAct((id: string) => unwrap(deleteClientProviderAction(tenantId, id)), () => "Provider removed");
  const test = useMutation({ mutationFn: (id: string) => unwrap(testClientProviderAction(tenantId, id)), onSuccess: (r) => (r.ok ? toast.success(r.message) : toast.error(r.message)), onError: (e) => toast.error(e instanceof Error ? e.message : "Test failed") });
  const pref = useAct(({ key, id }: { key: string; id: string | null }) => unwrap(saveMyModelPreferenceAction(key, id)), () => "Your model choice saved");
  const pct = budget ? Math.min(100, Math.round((spend.spent / budget) * 100)) : null;
  const usable = providers.filter((p) => !p.blocked);

  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-lg border p-3 text-xs">
        <p className="text-sm font-medium">What may run on this client&apos;s evidence</p>
        <p className="mt-1 text-muted-foreground">{rulesText} Set in the rulebook&apos;s data-handling block, signed by the client.</p>
      </div>

      <div className="rounded-lg border p-3">
        <p className="text-sm font-medium">Which model each agent gets now</p>
        <table className="mt-2 w-full text-xs">
          <thead className="text-left text-muted-foreground"><tr><th className="py-1">Agent</th><th>Model</th><th>Picked by</th><th>Notes</th></tr></thead>
          <tbody>
            {agents.map((a) => (
              <tr key={a.key} className="border-t align-top">
                <td className="py-1.5 pr-2 font-medium">{a.name}</td>
                <td className="pr-2">{a.resolution.provider ? <><span>{a.resolution.provider}</span><p className="font-mono text-[11px] text-muted-foreground">{a.resolution.model}</p></> : <span className="text-muted-foreground">built-in engine</span>}</td>
                <td className="pr-2"><Badge variant={a.resolution.source === "builtin" ? "outline" : "secondary"}>{SOURCE[a.resolution.source]}</Badge></td>
                <td className="text-[11px] text-muted-foreground">
                  {a.resolution.redacted && <p>Personal data masked before it reaches the model.</p>}
                  {a.resolution.clientKey && <p>Runs on the client&apos;s own key (billed to them).</p>}
                  {a.resolution.autonomyCap && <p className="text-warning">{a.resolution.capReason}</p>}
                  {a.resolution.skipped.map((s) => <p key={s.name}>Skipped {s.name}: {s.why}.</p>)}
                  {a.resolution.source === "builtin" && <p>{a.resolution.reason}</p>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="rounded-lg border p-3">
        <div className="flex flex-wrap items-center gap-2">
          <p className="text-sm font-medium">The client&apos;s choices</p>
          <p className="text-xs text-muted-foreground">A provider per agent (only ones the rulebook allows), and a monthly budget for the AI HELIOS pays for. At 80% the SOC manager is alerted; at 100% low- and medium-severity cases use the built-in engine.</p>
        </div>
        <div className="mt-2 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {agents.filter((a) => a.key !== "containment").map((a) => (
            <div key={a.key} className="grid gap-1">
              <Label className="text-xs">{a.name}</Label>
              <NativeSelect className="h-8 text-xs" disabled={!canEdit} value={choice[a.key] ?? ""} onChange={(e) => setChoice({ ...choice, [a.key]: e.target.value })} aria-label={`${a.name} provider`}>
                <option value="">Platform default</option>
                {usable.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.model}</option>)}
              </NativeSelect>
            </div>
          ))}
        </div>
        <div className="mt-3 flex flex-wrap items-end gap-3">
          <div className="grid gap-1">
            <Label htmlFor="ai-budget" className="text-xs">Monthly budget (USD)</Label>
            <Input id="ai-budget" type="number" min={0} className="h-8 w-36" disabled={!canEdit} value={limit} onChange={(e) => setLimit(e.target.value)} placeholder="No limit" />
          </div>
          <div className="text-xs">
            <p>This month: <span className="font-medium">${spend.spent.toFixed(2)}</span>{budget ? ` of $${budget.toFixed(2)} (${pct}%)` : ""} · {spend.runs} runs{spend.clientKeyRuns ? `, ${spend.clientKeyRuns} on the client's key` : ""}</p>
            {pct != null && <div className="mt-1 h-1.5 w-56 rounded bg-muted"><div className={cn("h-1.5 rounded", pct >= 100 ? "bg-destructive" : pct >= 80 ? "bg-warning" : "bg-primary")} style={{ width: `${pct}%` }} /></div>}
          </div>
          {canEdit && (
            <Button size="sm" className="ml-auto" onClick={() => savePolicy.mutate(undefined)} disabled={savePolicy.isPending}>
              {savePolicy.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save choices
            </Button>
          )}
        </div>
      </div>

      <div className="rounded-lg border p-3">
        <p className="text-sm font-medium">Providers</p>
        <p className="text-xs text-muted-foreground">The platform&apos;s providers and the client&apos;s own (bring your own key: used only for this client, and billed to the client directly). Keys are sealed and never shown again.</p>
        <ul className="mt-2 flex flex-col gap-1.5">
          {providers.map((p) => (
            <li key={p.id} className="flex flex-wrap items-center gap-2 text-xs">
              <span className="font-medium">{p.name}</span>
              <span className="font-mono text-muted-foreground">{p.model}</span>
              {p.isLocal && <Badge variant="outline">local</Badge>}
              {p.region && <Badge variant="outline">{p.region}</Badge>}
              {p.own && <Badge variant="secondary"><KeyRound className="size-3" /> client&apos;s key</Badge>}
              {p.blocked ? <span className="text-destructive">not allowed: {p.blocked}</span> : <span className="text-success">allowed</span>}
              {p.own && canEdit && (
                <span className="ml-auto flex gap-1">
                  <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => test.mutate(p.id)} disabled={test.isPending}><Radio /> Test</Button>
                  <Button size="icon" variant="ghost" className="size-7" onClick={() => remove.mutate(p.id)} aria-label={`Remove ${p.name}`}><Trash2 /></Button>
                </span>
              )}
              {p.own && p.lastCheckOk != null && <span className={cn("w-full text-[11px]", p.lastCheckOk ? "text-muted-foreground" : "text-destructive")}>Last test: {p.lastCheckMessage}</span>}
            </li>
          ))}
        </ul>
        {canEdit && !adding && <Button size="sm" variant="outline" className="mt-2 h-7 text-xs" onClick={() => setAdding(true)}><Plus /> Add the client&apos;s own provider</Button>}
        {canEdit && adding && (
          <div className="mt-2 grid gap-2 rounded-md border p-2 sm:grid-cols-2">
            <div className="grid gap-1"><Label className="text-xs" htmlFor="cp-name">Name</Label><Input id="cp-name" className="h-8 text-xs" value={d.name} onChange={(e) => setD({ ...d, name: e.target.value })} placeholder="Our Claude account" /></div>
            <div className="grid gap-1">
              <Label className="text-xs" htmlFor="cp-kind">Kind</Label>
              <NativeSelect id="cp-kind" className="h-8 text-xs" value={d.kind} onChange={(e) => setD({ ...d, kind: e.target.value as ProviderKind, model: KIND_DEFAULT_MODEL[e.target.value as ProviderKind], region: e.target.value === "bedrock" ? "ap-south-1" : d.region })}>
                <option value="anthropic">Anthropic API</option>
                <option value="bedrock">Claude in Amazon Bedrock (your AWS account)</option>
                <option value="azure_openai">Azure OpenAI (your Azure resource)</option>
                <option value="openai_compatible">OpenAI-compatible endpoint (HELIOS AI box, vLLM, Ollama…)</option>
              </NativeSelect>
            </div>
            {(d.kind === "openai_compatible" || d.kind === "azure_openai") && (
              <div className="grid gap-1 sm:col-span-2">
                <Label className="text-xs" htmlFor="cp-url">{d.kind === "azure_openai" ? "Endpoint" : "Base URL"}</Label>
                <Input id="cp-url" className="h-8 text-xs" value={d.baseUrl} onChange={(e) => setD({ ...d, baseUrl: e.target.value })} placeholder={d.kind === "azure_openai" ? "https://NAME.openai.azure.com" : "https://ai-box.client.example/v1"} />
              </div>
            )}
            <div className="grid gap-1"><Label className="text-xs" htmlFor="cp-model">{d.kind === "azure_openai" ? "Deployment name" : "Model"}</Label><Input id="cp-model" className="h-8 font-mono text-xs" value={d.model} onChange={(e) => setD({ ...d, model: e.target.value })} /></div>
            <div className="grid gap-1"><Label className="text-xs" htmlFor="cp-key">{d.kind === "bedrock" ? "Bedrock API key (or an access key below)" : "API key"}</Label><Input id="cp-key" type="password" className="h-8 text-xs" value={d.apiKey} onChange={(e) => setD({ ...d, apiKey: e.target.value })} autoComplete="off" /></div>
            {d.kind === "bedrock" && (
              <>
                <div className="grid gap-1"><Label className="text-xs" htmlFor="cp-aws-id">Access key ID</Label><Input id="cp-aws-id" className="h-8 text-xs" value={d.awsAccessKeyId} onChange={(e) => setD({ ...d, awsAccessKeyId: e.target.value })} autoComplete="off" /></div>
                <div className="grid gap-1"><Label className="text-xs" htmlFor="cp-aws-secret">Secret access key</Label><Input id="cp-aws-secret" type="password" className="h-8 text-xs" value={d.awsSecretAccessKey} onChange={(e) => setD({ ...d, awsSecretAccessKey: e.target.value })} autoComplete="off" /></div>
              </>
            )}
            <div className="grid gap-1"><Label className="text-xs" htmlFor="cp-region">{d.kind === "bedrock" ? "AWS region" : "Region"}</Label><Input id="cp-region" className="h-8 text-xs" value={d.region} onChange={(e) => setD({ ...d, region: e.target.value })} placeholder={d.kind === "bedrock" ? "ap-south-1" : "india, eu… (for region-locked rules)"} /></div>
            {d.kind === "openai_compatible" && <label className="flex items-center gap-2 self-end text-xs"><Switch checked={d.isLocal} onCheckedChange={(v) => setD({ ...d, isLocal: v })} /> Runs on the client&apos;s premises</label>}
            <div className="flex gap-2 sm:col-span-2">
              <Button size="sm" onClick={() => addProvider.mutate(undefined)} disabled={addProvider.isPending || d.name.length < 2 || !d.model}>{addProvider.isPending ? <Loader2 className="animate-spin" /> : <Save />} Add provider</Button>
              <Button size="sm" variant="ghost" onClick={() => setAdding(false)}>Cancel</Button>
            </div>
          </div>
        )}
      </div>

      {mine && (
        <div className="rounded-lg border p-3">
          <p className="text-sm font-medium">Your own model</p>
          <p className="text-xs text-muted-foreground">This client lets analysts choose. Your choice applies wherever a client allows it and the model is permitted there; a model you pick that hasn&apos;t passed evaluation only makes suggestions.</p>
          <div className="mt-2 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {agents.filter((a) => a.key !== "investigation").map((a) => (
              <div key={a.key} className="grid gap-1">
                <Label className="text-xs">{a.name}</Label>
                <NativeSelect className="h-8 text-xs" value={mine[a.key] ?? ""} onChange={(e) => pref.mutate({ key: a.key, id: e.target.value || null })} aria-label={`My model for ${a.name}`}>
                  <option value="">No preference</option>
                  {usable.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.model}</option>)}
                </NativeSelect>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
