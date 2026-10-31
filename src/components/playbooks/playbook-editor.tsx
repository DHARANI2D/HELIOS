"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Pencil, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import type { PlaybookActionType } from "@prisma/client";

import { savePlaybookAction, type PlaybookInput } from "@/app/(app)/playbooks/actions";
import type { TriggerCondition } from "@/lib/playbooks/trigger";
import { CASE_SOURCES, CASE_SOURCE_LABEL } from "@/lib/cases/labels";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { unwrap } from "@/lib/action-result";

const ACTION_TYPES: Array<{ value: PlaybookActionType; label: string; hint: string }> = [
  { value: "ISOLATE_HOST", label: "Isolate host", hint: "method=edr_network_containment" },
  { value: "BLOCK_IP", label: "Block IP", hint: "ip=<address> (blank = all case IPs)" },
  { value: "NOTIFY_SLACK", label: "Notify channel", hint: "message=<text; {{case.title}}, {{host}}, {{user}} are filled in>" },
  { value: "CREATE_TICKET", label: "Create ticket", hint: "title=<text; {{case.title}}, {{host}} are filled in>" },
  { value: "KILL_PROCESS", label: "Kill process", hint: "process=<image name>\nhost=<hostname> (blank = case host)" },
  { value: "COLLECT_LOGS", label: "Collect telemetry", hint: "windowMinutes=60" },
  { value: "REVOKE_AGENT", label: "Revoke AI agent", hint: "" },
  { value: "RESTORE_AGENT", label: "Restore AI agent", hint: "" },
  { value: "DISABLE_USER", label: "Disable account", hint: "user=<account> (blank = case account)" },
  { value: "ENABLE_USER", label: "Re-enable account", hint: "user=<account>" },
  { value: "QUARANTINE_FILE", label: "Quarantine file", hint: "hash=<sha256>" },
  { value: "BLOCK_SENDER", label: "Block sender", hint: "sender=<address or domain>" },
  { value: "RELEASE_HOST", label: "Release host", hint: "host=<hostname> (blank = case host)" },
  { value: "UNBLOCK_IP", label: "Unblock IP", hint: "ip=<address>" },
];

const DETECTION_SOURCES = [
  "THREAT_INTEL_MATCH",
  "CREDENTIAL_HARVESTING",
  "LATERAL_MOVEMENT",
  "DATA_EXFILTRATION",
  "PERSISTENCE",
  "DEFENSE_EVASION",
  "IMPACT",
  "RECONNAISSANCE",
  "GEO_VELOCITY",
  "FSM_CHAIN",
  "ANOMALOUS_ACTION",
  "AGENT_DLP",
  "AGENT_INTENT_POLICY",
  "AGENT_REASONING_DRIFT",
  "EMAIL_HEADER_AUTH",
  "EMAIL_BODY_URL",
  "EMAIL_ATTACHMENT_FORENSICS",
  "EMAIL_SANDBOX_DETONATION",
  "VENDOR_ALERT",
];

export interface EditablePlaybook {
  id: string;
  name: string;
  description: string | null;
  triggerCondition: TriggerCondition;
  autoExecute: boolean;
  requireApproval: boolean;
  priority: number;
  actions: Array<{ name: string; actionType: PlaybookActionType; parameters: Record<string, string | number> }>;
}

interface ActionDraft {
  name: string;
  actionType: PlaybookActionType;
  params: string; // key=value per line
}

function paramsToText(params: Record<string, string | number>) {
  return Object.entries(params)
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");
}

function textToParams(text: string): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  for (const line of text.split("\n")) {
    const idx = line.indexOf("=");
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim();
    const raw = line.slice(idx + 1).trim();
    if (!key) continue;
    out[key] = raw !== "" && /^\d+(\.\d+)?$/.test(raw) ? Number(raw) : raw;
  }
  return out;
}

const splitList = (text: string) =>
  text
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);

export function PlaybookEditor({ playbook }: { playbook?: EditablePlaybook }) {
  const router = useRouter();
  const [open, setOpen] = React.useState(false);
  const t = playbook?.triggerCondition ?? {};

  const [name, setName] = React.useState(playbook?.name ?? "");
  const [description, setDescription] = React.useState(playbook?.description ?? "");
  const [minSeverity, setMinSeverity] = React.useState(t.minSeverity ?? "");
  const [sourceTypes, setSourceTypes] = React.useState<string[]>(t.sourceTypes ?? []);
  const [techniques, setTechniques] = React.useState((t.techniques ?? []).join(", "));
  const [detectionSources, setDetectionSources] = React.useState<string[]>(t.detectionSources ?? []);
  const [minRiskScore, setMinRiskScore] = React.useState(t.minRiskScore?.toString() ?? "");
  const [verdicts, setVerdicts] = React.useState((t.verdicts ?? []).join(", "));
  const [autoExecute, setAutoExecute] = React.useState(playbook?.autoExecute ?? false);
  const [requireApproval, setRequireApproval] = React.useState(playbook?.requireApproval ?? true);
  const [priority, setPriority] = React.useState(playbook?.priority ?? 50);
  const [actions, setActions] = React.useState<ActionDraft[]>(
    playbook?.actions.map((a) => ({ name: a.name, actionType: a.actionType, params: paramsToText(a.parameters) })) ?? [
      { name: "Notify SOC channel", actionType: "NOTIFY_SLACK", params: "channel=#soc\nmessage=HELIOS: {{case.title}}" },
    ],
  );

  const save = useMutation({
    mutationFn: () => {
      const trigger: TriggerCondition = {};
      if (minSeverity) trigger.minSeverity = minSeverity as TriggerCondition["minSeverity"];
      if (sourceTypes.length) trigger.sourceTypes = sourceTypes as TriggerCondition["sourceTypes"];
      if (splitList(techniques).length) trigger.techniques = splitList(techniques).map((x) => x.toUpperCase());
      if (detectionSources.length) trigger.detectionSources = detectionSources;
      if (minRiskScore) trigger.minRiskScore = Number(minRiskScore);
      if (splitList(verdicts).length) trigger.verdicts = splitList(verdicts).map((v) => v.toLowerCase());
      const input: PlaybookInput = {
        name,
        description: description || undefined,
        triggerCondition: trigger,
        autoExecute,
        requireApproval,
        priority,
        actions: actions.map((a) => ({ name: a.name, actionType: a.actionType, parameters: textToParams(a.params) })),
      };
      return unwrap(savePlaybookAction(input, playbook?.id));
    },
    onSuccess: () => {
      toast.success(playbook ? "Playbook updated" : "Playbook created");
      setOpen(false);
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message.split("\n")[0] : "Save failed"),
  });

  const toggle = (list: string[], set: (v: string[]) => void, value: string) =>
    set(list.includes(value) ? list.filter((x) => x !== value) : [...list, value]);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {playbook ? (
          <Button size="sm" variant="ghost"><Pencil /> Edit</Button>
        ) : (
          <Button><Plus /> New playbook</Button>
        )}
      </DialogTrigger>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{playbook ? "Edit playbook" : "New playbook"}</DialogTitle>
          <DialogDescription>Triggers match any case source. All conditions must hold; list conditions match any item.</DialogDescription>
        </DialogHeader>

        <div className="grid gap-4">
          <div className="grid gap-1.5">
            <Label htmlFor="pb-name">Name</Label>
            <Input id="pb-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="pb-desc">Description</Label>
            <Textarea id="pb-desc" value={description} onChange={(e) => setDescription(e.target.value)} className="min-h-14" />
          </div>

          <fieldset className="grid gap-3 rounded-md border p-3">
            <legend className="px-1 text-sm font-medium">Trigger</legend>
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-1.5">
                <Label htmlFor="pb-sev" className="text-xs">Minimum severity</Label>
                <NativeSelect id="pb-sev" value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
                  <option value="">Any</option>
                  {[...SEVERITY_ORDER].reverse().map((s) => (
                    <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>
                  ))}
                </NativeSelect>
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="pb-risk" className="text-xs">Minimum risk score</Label>
                <Input id="pb-risk" type="number" min={0} max={1000} value={minRiskScore} onChange={(e) => setMinRiskScore(e.target.value)} />
              </div>
            </div>
            <div className="grid gap-1.5">
              <span className="text-xs font-medium">Case sources</span>
              <div className="flex flex-wrap gap-3">
                {CASE_SOURCES.map((s) => (
                  <label key={s} className="flex items-center gap-1.5 text-sm">
                    <input type="checkbox" checked={sourceTypes.includes(s)} onChange={() => toggle(sourceTypes, setSourceTypes, s)} />
                    {CASE_SOURCE_LABEL[s]}
                  </label>
                ))}
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-1.5">
                <Label htmlFor="pb-tech" className="text-xs">ATT&amp;CK techniques</Label>
                <Input id="pb-tech" value={techniques} onChange={(e) => setTechniques(e.target.value)} placeholder="ATT&CK IDs, comma-separated" className="font-mono" />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="pb-verdict" className="text-xs">Verdicts</Label>
                <Input id="pb-verdict" value={verdicts} onChange={(e) => setVerdicts(e.target.value)} placeholder="Verdicts, comma-separated" />
              </div>
            </div>
            <details>
              <summary className="cursor-pointer text-xs font-medium">Detection sources ({detectionSources.length} selected)</summary>
              <div className="mt-2 grid grid-cols-2 gap-1.5">
                {DETECTION_SOURCES.map((s) => (
                  <label key={s} className="flex items-center gap-1.5 font-mono text-[11px]">
                    <input type="checkbox" checked={detectionSources.includes(s)} onChange={() => toggle(detectionSources, setDetectionSources, s)} />
                    {s}
                  </label>
                ))}
              </div>
            </details>
          </fieldset>

          <div className="flex flex-wrap items-center gap-6">
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={requireApproval} onCheckedChange={setRequireApproval} /> Require approval
            </label>
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={autoExecute} onCheckedChange={setAutoExecute} disabled={requireApproval} /> Auto-execute
            </label>
            <div className="flex items-center gap-2">
              <Label htmlFor="pb-prio" className="text-sm">Priority</Label>
              <Input id="pb-prio" type="number" min={0} max={1000} value={priority} onChange={(e) => setPriority(Number(e.target.value) || 0)} className="w-20" />
            </div>
          </div>
          <p className="-mt-2 text-xs text-muted-foreground">
            {requireApproval
              ? "Matches queue for admin approval before any action runs."
              : autoExecute
                ? "Matches run immediately, unattended."
                : "Manual only — offered as a suggestion on matching cases."}
          </p>

          <fieldset className="grid gap-3 rounded-md border p-3">
            <legend className="px-1 text-sm font-medium">Actions (run in order)</legend>
            {actions.map((a, i) => (
              <div key={i} className="grid gap-2 rounded-md bg-muted/40 p-2">
                <div className="flex gap-2">
                  <NativeSelect
                    value={a.actionType}
                    onChange={(e) => setActions(actions.map((x, j) => (j === i ? { ...x, actionType: e.target.value as PlaybookActionType } : x)))}
                    aria-label="Action type"
                  >
                    {ACTION_TYPES.map((t) => (
                      <option key={t.value} value={t.value}>{t.label}</option>
                    ))}
                  </NativeSelect>
                  <Input value={a.name} onChange={(e) => setActions(actions.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)))} placeholder="Step name" />
                  <Button variant="ghost" size="icon" onClick={() => setActions(actions.filter((_, j) => j !== i))} aria-label="Remove action">
                    <Trash2 />
                  </Button>
                </div>
                <Textarea
                  value={a.params}
                  onChange={(e) => setActions(actions.map((x, j) => (j === i ? { ...x, params: e.target.value } : x)))}
                  placeholder={ACTION_TYPES.find((t) => t.value === a.actionType)?.hint || "No parameters"}
                  className="min-h-12 font-mono text-xs"
                />
              </div>
            ))}
            <Button
              variant="outline"
              size="sm"
              onClick={() => setActions([...actions, { name: "New step", actionType: "CREATE_TICKET", params: "" }])}
            >
              <Plus /> Add action
            </Button>
            <p className="text-xs text-muted-foreground">
              Parameters are <code>key=value</code> lines. Templates: <code>{"{{case.title}}"}</code>, <code>{"{{case.severity}}"}</code>,{" "}
              <code>{"{{host}}"}</code>, <code>{"{{user}}"}</code>, <code>{"{{ips}}"}</code>.
            </p>
          </fieldset>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={() => save.mutate()} disabled={save.isPending || name.trim().length < 3 || actions.length === 0}>
            {save.isPending && <Loader2 className="animate-spin" />}
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
