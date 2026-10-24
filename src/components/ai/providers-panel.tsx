"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Cloud, HardDrive, Loader2, Pencil, Plus, PlugZap, Star, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { deleteProviderAction, saveProviderAction, setDefaultProviderAction, setProviderEnabledAction, testProviderAction } from "@/app/(app)/ai/actions";
import { PROVIDER_PRESETS } from "@/lib/ai/catalog";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";

export interface ProviderView {
  id: string;
  name: string;
  kind: "anthropic" | "openai_compatible";
  baseUrl: string | null;
  model: string;
  isLocal: boolean;
  enabled: boolean;
  isDefault: boolean;
  hasKey: boolean;
  lastCheckOk: boolean | null;
  lastCheckMessage: string | null;
  usedBy: number;
}

interface Props {
  providers: ProviderView[];
  envClaude: { available: boolean; model: string };
  canConfigure: boolean;
}

interface Draft {
  id?: string;
  preset: string;
  name: string;
  kind: "anthropic" | "openai_compatible";
  baseUrl: string;
  model: string;
  apiKey: string;
  isLocal: boolean;
  isDefault: boolean;
}

function draftFromPreset(id: string): Draft {
  const p = PROVIDER_PRESETS.find((x) => x.id === id) ?? PROVIDER_PRESETS[0];
  return { preset: p.id, name: p.label.replace(/ \(.*\)$/, ""), kind: p.kind, baseUrl: p.baseUrl ?? "", model: p.defaultModel, apiKey: "", isLocal: p.isLocal, isDefault: false };
}

export function ProvidersPanel({ providers, envClaude, canConfigure }: Props) {
  const router = useRouter();
  const [draft, setDraft] = React.useState<Draft | null>(null);
  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed");
  const refresh = (msg: string) => {
    toast.success(msg);
    router.refresh();
  };

  const save = useMutation({
    mutationFn: (d: Draft) => saveProviderAction({ id: d.id, name: d.name, kind: d.kind, baseUrl: d.baseUrl, model: d.model, apiKey: d.apiKey || undefined, isLocal: d.isLocal, isDefault: d.isDefault }),
    onSuccess: () => {
      setDraft(null);
      refresh("Provider saved");
    },
    onError,
  });
  const test = useMutation({
    mutationFn: (id: string) => testProviderAction(id),
    onSuccess: (r) => {
      if (r.ok) toast.success(r.message);
      else toast.error(r.message);
      router.refresh();
    },
    onError,
  });
  const enable = useMutation({ mutationFn: ({ id, on }: { id: string; on: boolean }) => setProviderEnabledAction(id, on), onSuccess: () => refresh("Updated"), onError });
  const makeDefault = useMutation({ mutationFn: (id: string | null) => setDefaultProviderAction(id), onSuccess: () => refresh("Default provider updated"), onError });
  const remove = useMutation({ mutationFn: (id: string) => deleteProviderAction(id), onSuccess: () => refresh("Provider removed"), onError });

  const preset = draft ? PROVIDER_PRESETS.find((p) => p.id === draft.preset) : undefined;
  const hasDefault = providers.some((p) => p.isDefault && p.enabled);

  return (
    <div className="flex flex-col gap-3">
      <ul className="flex flex-col gap-2">
        <li className={cn("flex flex-wrap items-center gap-3 rounded-lg border p-3", !envClaude.available && "opacity-60")}>
          <Cloud className="size-4 text-muted-foreground" />
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium">Claude (environment key)</p>
            <p className="text-xs text-muted-foreground">
              {envClaude.available ? `ANTHROPIC_API_KEY is set · ${envClaude.model}` : "ANTHROPIC_API_KEY not set"} · used when no provider below is the default
            </p>
          </div>
          {envClaude.available && !hasDefault && <Badge variant="success">In use</Badge>}
          {envClaude.available && canConfigure && (
            <Button size="sm" variant="ghost" onClick={() => test.mutate("env")} disabled={test.isPending}>
              {test.isPending && test.variables === "env" ? <Loader2 className="animate-spin" /> : <PlugZap />} Test
            </Button>
          )}
        </li>
        {providers.map((p) => (
          <li key={p.id} className={cn("flex flex-wrap items-center gap-3 rounded-lg border p-3", !p.enabled && "opacity-60")}>
            {p.isLocal ? <HardDrive className="size-4 text-muted-foreground" /> : <Cloud className="size-4 text-muted-foreground" />}
            <div className="min-w-0 flex-1">
              <p className="flex flex-wrap items-center gap-1.5 text-sm font-medium">
                {p.name}
                <Badge variant={p.isLocal ? "info" : "soft"}>{p.isLocal ? "Local / offline" : "Online"}</Badge>
                {p.isDefault && <Badge variant="default"><Star /> Default</Badge>}
              </p>
              <p className="truncate text-xs text-muted-foreground">
                <code>{p.model}</code>
                {p.baseUrl ? ` · ${p.baseUrl}` : ""}
                {p.hasKey ? " · key stored (encrypted)" : ""}
                {p.usedBy ? ` · ${p.usedBy} agent profile${p.usedBy === 1 ? "" : "s"}` : ""}
              </p>
              {p.lastCheckMessage && <p className={cn("text-xs", p.lastCheckOk ? "text-success-ink" : "text-destructive")}>{p.lastCheckMessage}</p>}
            </div>
            {canConfigure && (
              <div className="flex items-center gap-1">
                <Button size="sm" variant="ghost" onClick={() => test.mutate(p.id)} disabled={test.isPending}>
                  {test.isPending && test.variables === p.id ? <Loader2 className="animate-spin" /> : <PlugZap />} Test
                </Button>
                {!p.isDefault && p.enabled && (
                  <Button size="sm" variant="ghost" onClick={() => makeDefault.mutate(p.id)} disabled={makeDefault.isPending}>
                    <Star /> Make default
                  </Button>
                )}
                {p.isDefault && (
                  <Button size="sm" variant="ghost" onClick={() => makeDefault.mutate(null)} disabled={makeDefault.isPending}>
                    Unset default
                  </Button>
                )}
                <Button
                  size="icon"
                  variant="ghost"
                  aria-label="Edit"
                  onClick={() => setDraft({ id: p.id, preset: p.kind === "anthropic" ? "claude" : "ollama", name: p.name, kind: p.kind, baseUrl: p.baseUrl ?? "", model: p.model, apiKey: "", isLocal: p.isLocal, isDefault: p.isDefault })}
                >
                  <Pencil />
                </Button>
                <Switch checked={p.enabled} onCheckedChange={(on) => enable.mutate({ id: p.id, on })} aria-label="Enabled" />
                {p.usedBy === 0 && (
                  <Button size="icon" variant="ghost" aria-label="Delete" onClick={() => remove.mutate(p.id)}>
                    <Trash2 />
                  </Button>
                )}
              </div>
            )}
          </li>
        ))}
      </ul>
      {canConfigure && (
        <div className="flex flex-wrap gap-2">
          {PROVIDER_PRESETS.map((p) => (
            <Button key={p.id} size="sm" variant="outline" onClick={() => setDraft(draftFromPreset(p.id))}>
              <Plus /> {p.label}
            </Button>
          ))}
        </div>
      )}

      <Dialog open={!!draft} onOpenChange={(o) => !o && setDraft(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{draft?.id ? "Edit provider" : "Add AI provider"}</DialogTitle>
            <DialogDescription>{preset?.note ?? "Credentials are encrypted at rest and never shown again."}</DialogDescription>
          </DialogHeader>
          {draft && (
            <div className="grid gap-3">
              <div className="grid gap-1.5">
                <Label>Name</Label>
                <Input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
              </div>
              {draft.kind === "openai_compatible" && (
                <div className="grid gap-1.5">
                  <Label>Base URL (OpenAI-compatible /v1)</Label>
                  <Input value={draft.baseUrl} onChange={(e) => setDraft({ ...draft, baseUrl: e.target.value })} placeholder="http://localhost:11434/v1" />
                </div>
              )}
              <div className="grid gap-1.5">
                <Label>Model</Label>
                <Input value={draft.model} onChange={(e) => setDraft({ ...draft, model: e.target.value })} list="model-suggestions" />
                <datalist id="model-suggestions">
                  {(preset?.models ?? []).map((m) => (
                    <option key={m} value={m} />
                  ))}
                </datalist>
              </div>
              <div className="grid gap-1.5">
                <Label>{draft.kind === "anthropic" ? "Anthropic API key" : "API key (optional)"}</Label>
                <Input type="password" value={draft.apiKey} onChange={(e) => setDraft({ ...draft, apiKey: e.target.value })} placeholder={draft.id ? "Leave blank to keep the stored key" : draft.kind === "anthropic" ? "sk-ant-…" : "Only if your server requires one"} autoComplete="off" />
              </div>
              {draft.kind === "openai_compatible" && (
                <label className="flex items-center gap-2 text-sm">
                  <Switch checked={draft.isLocal} onCheckedChange={(v) => setDraft({ ...draft, isLocal: v })} />
                  Runs on infrastructure we control (telemetry stays on-prem)
                </label>
              )}
              <label className="flex items-center gap-2 text-sm">
                <Switch checked={draft.isDefault} onCheckedChange={(v) => setDraft({ ...draft, isDefault: v })} />
                Use as the platform default for every agent
              </label>
            </div>
          )}
          <DialogFooter>
            <Button variant="ghost" onClick={() => setDraft(null)}>Cancel</Button>
            <Button onClick={() => draft && save.mutate(draft)} disabled={save.isPending}>
              {save.isPending && <Loader2 className="animate-spin" />}
              Save provider
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
