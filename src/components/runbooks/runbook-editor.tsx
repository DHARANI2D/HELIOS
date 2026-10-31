"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, Loader2, Plus, Save, Sparkles, Trash2, X } from "lucide-react";
import { toast } from "sonner";

import { deleteRunbookAction, installTemplatesAction, saveRunbookAction, setRunbookEnabledAction } from "@/app/(app)/runbooks/actions";
import { CASE_SOURCES, type RunbookInput, type RunbookStep } from "@/lib/runbooks/match";
import type { CaseSource } from "@prisma/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { unwrap } from "@/lib/action-result";

const onError = (e: Error) => toast.error(e.message);
const list = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);

export interface RunbookDraft extends RunbookInput {
  id: string | null;
  tenantId: string | null;
}

const EMPTY: RunbookDraft = { id: null, tenantId: null, title: "", description: "", match: { sources: [], techniques: [], keywords: [], minSeverity: null }, steps: [{ id: "s1", title: "", detail: "", required: true }] };

export function RunbookEditor({ initial, tenants, onDone }: { initial?: RunbookDraft; tenants: Array<{ id: string; name: string }>; onDone?: () => void }) {
  const router = useRouter();
  const [d, setD] = React.useState<RunbookDraft>(initial ?? EMPTY);
  const [techniques, setTechniques] = React.useState(d.match.techniques.join(", "));
  const [keywords, setKeywords] = React.useState(d.match.keywords.join(", "));
  const setStep = (i: number, patch: Partial<RunbookStep>) => setD((x) => ({ ...x, steps: x.steps.map((s, j) => (j === i ? { ...s, ...patch } : s)) }));
  const move = (i: number, by: number) => setD((x) => {
    const steps = [...x.steps];
    const [s] = steps.splice(i, 1);
    steps.splice(Math.max(0, Math.min(steps.length, i + by)), 0, s);
    return { ...x, steps };
  });
  const nextId = () => {
    let n = d.steps.length + 1;
    while (d.steps.some((s) => s.id === `s${n}`)) n++;
    return `s${n}`;
  };
  const save = useMutation({
    mutationFn: () => unwrap(saveRunbookAction(d.id, { ...d, match: { ...d.match, techniques: list(techniques), keywords: list(keywords) } })),
    onSuccess: () => { toast.success("Runbook saved"); if (!d.id) setD(EMPTY); onDone?.(); router.refresh(); },
    onError,
  });
  const sourceOn = (s: CaseSource) => d.match.sources.includes(s);
  return (
    <div className="flex flex-col gap-3">
      <div className="grid gap-2 sm:grid-cols-[1fr_14rem]">
        <div className="grid gap-1"><Label htmlFor="rb-title" className="text-xs">Title</Label><Input id="rb-title" className="h-8 text-sm" value={d.title} onChange={(e) => setD({ ...d, title: e.target.value })} /></div>
        <div className="grid gap-1">
          <Label htmlFor="rb-client" className="text-xs">For</Label>
          <NativeSelect id="rb-client" className="h-8 text-xs" value={d.tenantId ?? ""} onChange={(e) => setD({ ...d, tenantId: e.target.value || null })}>
            <option value="">Every client</option>
            {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </NativeSelect>
        </div>
      </div>
      <div className="grid gap-1"><Label htmlFor="rb-desc" className="text-xs">What it&apos;s for</Label><Textarea id="rb-desc" className="min-h-14 text-xs" value={d.description} onChange={(e) => setD({ ...d, description: e.target.value })} /></div>
      <fieldset className="grid gap-2 rounded-md border p-3">
        <legend className="px-1 text-xs text-muted-foreground">Which cases it&apos;s attached to</legend>
        <div className="grid gap-2 sm:grid-cols-2">
          <div className="grid gap-1"><Label htmlFor="rb-tech" className="text-xs">ATT&amp;CK techniques (comma-separated; T1566 also matches T1566.001)</Label><Input id="rb-tech" className="h-8 font-mono text-xs" value={techniques} onChange={(e) => setTechniques(e.target.value)} /></div>
          <div className="grid gap-1"><Label htmlFor="rb-kw" className="text-xs">Title keywords (a keyword matches words starting with it)</Label><Input id="rb-kw" className="h-8 text-xs" value={keywords} onChange={(e) => setKeywords(e.target.value)} /></div>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-xs">
          <span className="text-muted-foreground">Only cases from:</span>
          {(Object.keys(CASE_SOURCES) as CaseSource[]).map((s) => (
            <label key={s} className="flex items-center gap-1"><input type="checkbox" checked={sourceOn(s)} onChange={() => setD({ ...d, match: { ...d.match, sources: sourceOn(s) ? d.match.sources.filter((x) => x !== s) : [...d.match.sources, s] } })} /> {CASE_SOURCES[s]}</label>
          ))}
          <span className="text-muted-foreground">(none ticked: any)</span>
          <span className="ml-auto flex items-center gap-1">
            <Label htmlFor="rb-sev" className="text-xs">At least</Label>
            <NativeSelect id="rb-sev" className="h-7 text-xs" value={d.match.minSeverity ?? ""} onChange={(e) => setD({ ...d, match: { ...d.match, minSeverity: (e.target.value || null) as RunbookDraft["match"]["minSeverity"] } })}>
              <option value="">Any severity</option>
              {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => <option key={s} value={s}>{s.toLowerCase()}</option>)}
            </NativeSelect>
          </span>
        </div>
      </fieldset>
      <div className="flex flex-col gap-2">
        <p className="text-xs text-muted-foreground">Steps. A true positive can&apos;t be closed while a required step is neither done nor skipped with a reason.</p>
        {d.steps.map((s, i) => (
          <div key={s.id} className="grid gap-1 rounded-md border p-2 sm:grid-cols-[1.5rem_1fr_auto]">
            <span className="pt-1.5 text-xs text-muted-foreground tabular">{i + 1}.</span>
            <div className="grid gap-1">
              <Input aria-label={`Step ${i + 1}`} placeholder="What to do" className="h-8 text-sm" value={s.title} onChange={(e) => setStep(i, { title: e.target.value })} />
              <Input aria-label={`Step ${i + 1} detail`} placeholder="How, or what to look for (optional)" className="h-8 text-xs" value={s.detail} onChange={(e) => setStep(i, { detail: e.target.value })} />
            </div>
            <div className="flex items-center gap-1">
              <label className="flex items-center gap-1 text-xs"><input type="checkbox" checked={s.required} onChange={(e) => setStep(i, { required: e.target.checked })} /> required</label>
              <Button size="icon" variant="ghost" className="size-7" aria-label="Move up" disabled={i === 0} onClick={() => move(i, -1)}><ArrowUp className="size-3.5" /></Button>
              <Button size="icon" variant="ghost" className="size-7" aria-label="Move down" disabled={i === d.steps.length - 1} onClick={() => move(i, 1)}><ArrowDown className="size-3.5" /></Button>
              <Button size="icon" variant="ghost" className="size-7" aria-label="Remove step" disabled={d.steps.length === 1} onClick={() => setD({ ...d, steps: d.steps.filter((_, j) => j !== i) })}><X className="size-3.5" /></Button>
            </div>
          </div>
        ))}
        <div><Button size="sm" variant="ghost" onClick={() => setD({ ...d, steps: [...d.steps, { id: nextId(), title: "", detail: "", required: false }] })}><Plus /> Add a step</Button></div>
      </div>
      <div className="flex gap-2">
        <Button size="sm" disabled={save.isPending || d.title.trim().length < 3} onClick={() => save.mutate()}>{save.isPending ? <Loader2 className="animate-spin" /> : <Save />} {d.id ? "Save changes" : "Create runbook"}</Button>
        {onDone && <Button size="sm" variant="ghost" onClick={onDone}>Cancel</Button>}
      </div>
    </div>
  );
}

export function RunbookRow({ draft, enabled, tenants, canEdit, children }: { draft: RunbookDraft; enabled: boolean; tenants: Array<{ id: string; name: string }>; canEdit: boolean; children: React.ReactNode }) {
  const router = useRouter();
  const [editing, setEditing] = React.useState(false);
  const toggle = useMutation({ mutationFn: (on: boolean) => unwrap(setRunbookEnabledAction(draft.id!, on)), onSuccess: () => router.refresh(), onError });
  const del = useMutation({
    mutationFn: async () => {
      if (!confirm(`Delete "${draft.title}"? Cases keep the copy they have.`)) return;
      await unwrap(deleteRunbookAction(draft.id!));
    },
    onSuccess: () => router.refresh(),
    onError,
  });
  if (editing) return <div className="rounded-md border p-3"><RunbookEditor initial={draft} tenants={tenants} onDone={() => setEditing(false)} /></div>;
  return (
    <div className={`rounded-md border p-3 ${enabled ? "" : "opacity-60"}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">{children}</div>
        {canEdit && (
          <div className="flex shrink-0 items-center gap-1">
            <Switch aria-label={enabled ? "Switch off" : "Switch on"} checked={enabled} disabled={toggle.isPending} onCheckedChange={(on) => toggle.mutate(on)} />
            <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => setEditing(true)}>Edit</Button>
            <Button size="icon" variant="ghost" className="size-7" aria-label="Delete runbook" disabled={del.isPending} onClick={() => del.mutate()}><Trash2 className="size-3.5" /></Button>
          </div>
        )}
      </div>
    </div>
  );
}

export function InstallTemplates() {
  const router = useRouter();
  const go = useMutation({ mutationFn: () => unwrap(installTemplatesAction()), onSuccess: (n) => { toast.success(n ? `${n} starter runbooks added` : "The starter runbooks are already here"); router.refresh(); }, onError });
  return <Button size="sm" variant="outline" disabled={go.isPending} onClick={() => go.mutate()}>{go.isPending ? <Loader2 className="animate-spin" /> : <Sparkles />} Add the starter runbooks</Button>;
}
