"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Bot, Loader2, Save } from "lucide-react";
import { toast } from "sonner";
import type { AiAutonomy } from "@prisma/client";

import { saveAgentProfileAction } from "@/app/(app)/ai/actions";
import { AUTONOMY_LABEL, AUTONOMY_ORDER, type AgentKey } from "@/lib/ai/catalog";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";

export interface ProfileView {
  key: AgentKey;
  name: string;
  description: string;
  enabled: boolean;
  providerId: string | null;
  model: string | null;
  autonomy: AiAutonomy;
  effort: "low" | "medium" | "high";
  minConfidence: number;
  allowedActions: string[];
  instructions: string | null;
  engine: string;
  runs30d: number;
}

interface Props {
  profile: ProfileView;
  providers: Array<{ id: string; name: string; model: string; isLocal: boolean }>;
  actions: Array<{ value: string; label: string }>;
  canConfigure: boolean;
}

// The containment controller is policy, not a model: it gets autonomy,
// confidence and the action allowlist. Model-backed agents get a provider,
// model and effort.
export function AgentProfileCard({ profile, providers, actions, canConfigure }: Props) {
  const router = useRouter();
  const [p, setP] = React.useState(profile);
  const dirty = JSON.stringify(p) !== JSON.stringify(profile);
  const isController = p.key === "containment";

  const save = useMutation({
    mutationFn: () =>
      saveAgentProfileAction({
        key: p.key,
        enabled: p.enabled,
        providerId: p.providerId,
        model: p.model,
        autonomy: p.autonomy,
        effort: p.effort,
        minConfidence: p.minConfidence,
        allowedActions: p.allowedActions as never,
        instructions: p.instructions,
      }),
    onSuccess: () => {
      toast.success(`${p.name} saved`);
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });

  return (
    <div className={cn("flex flex-col gap-3 rounded-lg border p-4", !p.enabled && "opacity-70")}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2">
          <Bot className="mt-0.5 size-4 text-chart-4" />
          <div>
            <p className="text-sm font-semibold">{p.name}</p>
            <p className="text-xs text-muted-foreground">{p.description}</p>
          </div>
        </div>
        <Switch checked={p.enabled} onCheckedChange={(v) => setP({ ...p, enabled: v })} disabled={!canConfigure} aria-label="Enabled" />
      </div>
      <div className="flex flex-wrap gap-1.5 text-[11px]">
        {!isController && <Badge variant="soft">Runs on {p.engine}</Badge>}
        <Badge variant="soft">{p.runs30d} runs (30d)</Badge>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        {!isController && (
          <>
            <div className="grid gap-1.5">
              <Label className="text-xs">Provider</Label>
              <NativeSelect value={p.providerId ?? ""} onChange={(e) => setP({ ...p, providerId: e.target.value || null })} disabled={!canConfigure}>
                <option value="">Platform default</option>
                {providers.map((pr) => (
                  <option key={pr.id} value={pr.id}>
                    {pr.name} · {pr.model}{pr.isLocal ? " (local)" : ""}
                  </option>
                ))}
              </NativeSelect>
            </div>
            <div className="grid gap-1.5">
              <Label className="text-xs">Model override</Label>
              <Input value={p.model ?? ""} onChange={(e) => setP({ ...p, model: e.target.value || null })} placeholder="Provider's model" disabled={!canConfigure} />
            </div>
            <div className="grid gap-1.5">
              <Label className="text-xs">Reasoning effort</Label>
              <NativeSelect value={p.effort} onChange={(e) => setP({ ...p, effort: e.target.value as ProfileView["effort"] })} disabled={!canConfigure}>
                <option value="low">Low — fastest, cheapest</option>
                <option value="medium">Medium — balanced</option>
                <option value="high">High — most thorough</option>
              </NativeSelect>
            </div>
          </>
        )}
        <div className="grid gap-1.5">
          <Label className="text-xs">{isController ? "Containment autonomy" : "Autonomy"}</Label>
          <NativeSelect value={p.autonomy} onChange={(e) => setP({ ...p, autonomy: e.target.value as AiAutonomy })} disabled={!canConfigure}>
            {AUTONOMY_ORDER.filter((a) => isController || a === "OFF" || a === "SUGGEST").map((a) => (
              <option key={a} value={a}>{AUTONOMY_LABEL[a]}</option>
            ))}
          </NativeSelect>
        </div>
        {isController && (
          <div className="grid gap-1.5">
            <Label className="text-xs">Auto-contain only above confidence</Label>
            <div className="flex items-center gap-2">
              <input
                type="range"
                min={0.5}
                max={0.99}
                step={0.01}
                value={p.minConfidence}
                onChange={(e) => setP({ ...p, minConfidence: Number(e.target.value) })}
                disabled={!canConfigure}
                className="flex-1 accent-[var(--primary)]"
              />
              <span className="w-10 text-right text-sm tabular">{Math.round(p.minConfidence * 100)}%</span>
            </div>
          </div>
        )}
      </div>

      {isController && (
        <div className="grid gap-1.5">
          <Label className="text-xs">Pre-approved actions (executed automatically under Auto-contain)</Label>
          <div className="flex flex-wrap gap-1.5">
            {actions.map((a) => {
              const on = p.allowedActions.includes(a.value);
              const humanOnly = a.value === "DISABLE_USER" || a.value === "KILL_PROCESS";
              return (
                <button
                  key={a.value}
                  type="button"
                  disabled={!canConfigure || humanOnly}
                  title={humanOnly ? "Always needs a human approval" : undefined}
                  onClick={() => setP({ ...p, allowedActions: on ? p.allowedActions.filter((x) => x !== a.value) : [...p.allowedActions, a.value] })}
                  className={cn(
                    "rounded-full border px-2.5 py-0.5 text-xs transition-colors hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50",
                    on && "border-primary bg-primary text-primary-foreground hover:bg-primary/90",
                  )}
                >
                  {a.label}
                  {humanOnly ? " · human only" : ""}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {!isController && (
        <div className="grid gap-1.5">
          <Label className="text-xs">Extra instructions (house style, client context)</Label>
          <Textarea value={p.instructions ?? ""} onChange={(e) => setP({ ...p, instructions: e.target.value || null })} className="min-h-16 text-xs" placeholder="e.g. Our clients are mostly healthcare; flag anything touching PHI systems as high." disabled={!canConfigure} />
        </div>
      )}

      {canConfigure && dirty && (
        <div>
          <Button size="sm" onClick={() => save.mutate()} disabled={save.isPending}>
            {save.isPending ? <Loader2 className="animate-spin" /> : <Save />}
            Save
          </Button>
        </div>
      )}
    </div>
  );
}
