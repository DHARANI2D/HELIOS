"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, OctagonX, Save, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import type { CaseSeverity } from "@prisma/client";

import { saveAiSettingsAction, setKillSwitchAction } from "@/app/(app)/ai/actions";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";

interface Props {
  killSwitch: boolean;
  firstResponse: boolean;
  minSeverity: CaseSeverity;
  maxAutoActionsPerHour: number;
  canConfigure: boolean;
}

export function SafetyControls(props: Props) {
  const router = useRouter();
  const [firstResponse, setFirstResponse] = React.useState(props.firstResponse);
  const [minSeverity, setMinSeverity] = React.useState(props.minSeverity);
  const [maxAuto, setMaxAuto] = React.useState(props.maxAutoActionsPerHour);

  const kill = useMutation({
    mutationFn: (on: boolean) => setKillSwitchAction(on),
    onSuccess: (_, on) => {
      toast[on ? "warning" : "success"](on ? "Kill switch ON — AI agents can only suggest" : "Kill switch off — autonomy restored to profile settings");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  const save = useMutation({
    mutationFn: () => saveAiSettingsAction({ killSwitch: props.killSwitch, firstResponse, minSeverity, maxAutoActionsPerHour: maxAuto }),
    onSuccess: () => {
      toast.success("AI settings saved");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });

  return (
    <div className="flex flex-col gap-5">
      <div
        className={cn(
          "flex flex-wrap items-center justify-between gap-3 rounded-lg border p-4",
          props.killSwitch ? "border-destructive/50 bg-destructive/10" : "border-success/40 bg-success/5",
        )}
      >
        <div className="flex items-start gap-3">
          {props.killSwitch ? <OctagonX className="mt-0.5 size-5 text-destructive" /> : <ShieldCheck className="mt-0.5 size-5 text-success-ink" />}
          <div>
            <p className="text-sm font-semibold">{props.killSwitch ? "Kill switch engaged" : "AI autonomy active"}</p>
            <p className="text-xs text-muted-foreground">
              {props.killSwitch
                ? "No AI agent can execute or queue containment; every recommendation is suggest-only."
                : "Agents act within their profiles, each client's consent cap and the guardrails below."}
            </p>
          </div>
        </div>
        {props.canConfigure && (
          <Button variant={props.killSwitch ? "outline" : "destructive"} size="sm" onClick={() => kill.mutate(!props.killSwitch)} disabled={kill.isPending}>
            {kill.isPending ? <Loader2 className="animate-spin" /> : <OctagonX />}
            {props.killSwitch ? "Release kill switch" : "Engage kill switch"}
          </Button>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <label className="flex items-start gap-3 rounded-lg border p-3">
          <Switch checked={firstResponse} onCheckedChange={setFirstResponse} disabled={!props.canConfigure} className="mt-0.5" />
          <span>
            <span className="block text-sm font-medium">AI first response</span>
            <span className="block text-xs text-muted-foreground">Triage every new case automatically</span>
          </span>
        </label>
        <div className="grid gap-1.5 rounded-lg border p-3">
          <Label className="text-xs">Run on cases at or above</Label>
          <NativeSelect value={minSeverity} onChange={(e) => setMinSeverity(e.target.value as CaseSeverity)} disabled={!props.canConfigure}>
            {[...SEVERITY_ORDER].reverse().map((s) => (
              <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>
            ))}
          </NativeSelect>
        </div>
        <div className="grid gap-1.5 rounded-lg border p-3">
          <Label className="text-xs">Max unattended containment / client / hour</Label>
          <Input type="number" min={0} max={100} value={maxAuto} onChange={(e) => setMaxAuto(Number(e.target.value))} disabled={!props.canConfigure} />
        </div>
      </div>
      {props.canConfigure && (
        <div>
          <Button size="sm" onClick={() => save.mutate()} disabled={save.isPending}>
            {save.isPending ? <Loader2 className="animate-spin" /> : <Save />}
            Save guardrails
          </Button>
        </div>
      )}
    </div>
  );
}
