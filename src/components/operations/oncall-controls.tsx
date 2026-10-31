"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { BellRing, Check, Loader2, Save, Trash2, Wand2 } from "lucide-react";
import { toast } from "sonner";

import { acknowledgePageAction, addOverrideAction, deleteShiftAction, generateRotaAction, pageOnCallAction, saveOperationsSettingsAction } from "@/app/(app)/operations/actions";
import type { OperationsSettings } from "@/lib/settings";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";
import { unwrap } from "@/lib/action-result";

const onError = (e: Error) => toast.error(e.message);
// A datetime-local value is the browser's local time.
const iso = (local: string) => new Date(local).toISOString();

export interface StaffOption {
  id: string;
  name: string;
  role: string;
  phone: boolean;
}

export function RotaForm({ staff }: { staff: StaffOption[] }) {
  const router = useRouter();
  const [people, setPeople] = React.useState<string[]>([]);
  const [from, setFrom] = React.useState("");
  const [hours, setHours] = React.useState(12);
  const [shifts, setShifts] = React.useState(28);
  const [withBackup, setWithBackup] = React.useState(true);
  const toggle = (id: string) => setPeople((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]));
  const save = useMutation({
    mutationFn: () => unwrap(generateRotaAction({ userIds: people, from: iso(from), shiftHours: hours, shifts, withBackup })),
    onSuccess: (n) => { toast.success(`${n} shifts on the rota`); router.refresh(); },
    onError,
  });
  const name = (id: string) => staff.find((s) => s.id === id)?.name ?? id;
  return (
    <div className="flex flex-col gap-3">
      <div>
        <p className="mb-1 text-xs text-muted-foreground">Who is on the rotation, in order (tick them in the order they take turns):</p>
        <div className="flex flex-wrap gap-1.5">
          {staff.map((s) => (
            <button key={s.id} type="button" onClick={() => toggle(s.id)} className={`rounded-md border px-2 py-1 text-xs ${people.includes(s.id) ? "border-primary bg-primary/10" : "hover:bg-muted"}`}>
              {people.includes(s.id) && <span className="mr-1 font-mono">{people.indexOf(s.id) + 1}.</span>}
              {s.name} <span className="text-muted-foreground">· {s.role}{s.phone ? "" : " · no phone"}</span>
            </button>
          ))}
        </div>
        {people.length > 0 && <p className="mt-1 text-xs">Order: {people.map(name).join(" → ")}</p>}
      </div>
      <div className="grid gap-2 sm:grid-cols-[12rem_9rem_8rem_auto_auto] sm:items-end">
        <div className="grid gap-1"><Label htmlFor="rota-from" className="text-xs">First shift starts (your time)</Label><Input id="rota-from" type="datetime-local" className="h-8 text-xs" value={from} onChange={(e) => setFrom(e.target.value)} /></div>
        <div className="grid gap-1">
          <Label htmlFor="rota-hours" className="text-xs">Shift length</Label>
          <NativeSelect id="rota-hours" className="h-8 text-xs" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            <option value={8}>8 hours</option>
            <option value={12}>12 hours</option>
            <option value={24}>24 hours</option>
            <option value={168}>1 week</option>
          </NativeSelect>
        </div>
        <div className="grid gap-1"><Label htmlFor="rota-count" className="text-xs">Shifts</Label><Input id="rota-count" type="number" min={1} max={200} className="h-8 text-xs" value={shifts} onChange={(e) => setShifts(Number(e.target.value) || 0)} /></div>
        <label className="flex items-center gap-1.5 pb-1.5 text-xs"><input type="checkbox" checked={withBackup} onChange={(e) => setWithBackup(e.target.checked)} /> Backup: the next person</label>
        <Button size="sm" disabled={save.isPending || !people.length || !from} onClick={() => save.mutate()}>{save.isPending ? <Loader2 className="animate-spin" /> : <Wand2 />} Generate</Button>
      </div>
      <p className="text-xs text-muted-foreground">Generating replaces the regular shifts in that period; cover added by hand stays.</p>
    </div>
  );
}

export function OverrideForm({ staff }: { staff: StaffOption[] }) {
  const router = useRouter();
  const [userId, setUserId] = React.useState(staff[0]?.id ?? "");
  const [role, setRole] = React.useState("primary");
  const [startsAt, setStartsAt] = React.useState("");
  const [endsAt, setEndsAt] = React.useState("");
  const [note, setNote] = React.useState("");
  const save = useMutation({
    mutationFn: () => unwrap(addOverrideAction({ userId, role, startsAt: iso(startsAt), endsAt: iso(endsAt), note })),
    onSuccess: () => { toast.success("Cover added"); setNote(""); router.refresh(); },
    onError,
  });
  return (
    <div className="grid gap-2 sm:grid-cols-[12rem_7rem_11rem_11rem_1fr_auto] sm:items-end">
      <div className="grid gap-1"><Label htmlFor="ov-user" className="text-xs">Who covers</Label><NativeSelect id="ov-user" className="h-8 text-xs" value={userId} onChange={(e) => setUserId(e.target.value)}>{staff.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</NativeSelect></div>
      <div className="grid gap-1"><Label htmlFor="ov-role" className="text-xs">As</Label><NativeSelect id="ov-role" className="h-8 text-xs" value={role} onChange={(e) => setRole(e.target.value)}><option value="primary">Primary</option><option value="backup">Backup</option></NativeSelect></div>
      <div className="grid gap-1"><Label htmlFor="ov-from" className="text-xs">From</Label><Input id="ov-from" type="datetime-local" className="h-8 text-xs" value={startsAt} onChange={(e) => setStartsAt(e.target.value)} /></div>
      <div className="grid gap-1"><Label htmlFor="ov-to" className="text-xs">Until</Label><Input id="ov-to" type="datetime-local" className="h-8 text-xs" value={endsAt} onChange={(e) => setEndsAt(e.target.value)} /></div>
      <div className="grid gap-1"><Label htmlFor="ov-note" className="text-xs">Note (swap, leave…)</Label><Input id="ov-note" className="h-8 text-xs" value={note} onChange={(e) => setNote(e.target.value)} /></div>
      <Button size="sm" variant="outline" disabled={save.isPending || !userId || !startsAt || !endsAt} onClick={() => save.mutate()}>{save.isPending ? <Loader2 className="animate-spin" /> : <Check />} Add cover</Button>
    </div>
  );
}

export function DeleteShift({ id }: { id: string }) {
  const router = useRouter();
  const del = useMutation({ mutationFn: () => unwrap(deleteShiftAction(id)), onSuccess: () => router.refresh(), onError });
  return <Button size="icon" variant="ghost" className="size-7" aria-label="Delete shift" disabled={del.isPending} onClick={() => del.mutate()}><Trash2 className="size-3.5" /></Button>;
}

export function AcknowledgePage({ id }: { id: string }) {
  const router = useRouter();
  const ack = useMutation({ mutationFn: () => unwrap(acknowledgePageAction(id)), onSuccess: () => { toast.success("Page answered"); router.refresh(); }, onError });
  return <Button size="sm" className="h-7 text-xs" disabled={ack.isPending} onClick={() => ack.mutate()}>{ack.isPending ? <Loader2 className="animate-spin" /> : <Check />} I&apos;m on it</Button>;
}

export function PageOnCall({ caseId }: { caseId?: string }) {
  const router = useRouter();
  const [message, setMessage] = React.useState("");
  const page = useMutation({
    mutationFn: () => unwrap(pageOnCallAction({ caseId, message })),
    onSuccess: (r) => { toast.success(r.paged ? (r.level === 0 ? "Paged the on-call analyst" : r.level === 1 ? "Nobody is primary on call: paged the backup" : "Nobody is on call: paged the SOC managers") : "Nobody could be paged"); setMessage(""); router.refresh(); },
    onError,
  });
  return (
    <div className="flex flex-col gap-2">
      <Textarea aria-label="What the page is about" placeholder={caseId ? "What do you need from them?" : "What's happening?"} className="min-h-16 text-xs" value={message} onChange={(e) => setMessage(e.target.value)} />
      <Button size="sm" variant="outline" disabled={page.isPending || message.trim().length < 3} onClick={() => page.mutate()}>{page.isPending ? <Loader2 className="animate-spin" /> : <BellRing />} Page on-call</Button>
    </div>
  );
}

export function OperationsSettingsForm({ value }: { value: OperationsSettings }) {
  const router = useRouter();
  const [v, setV] = React.useState(value);
  const set = <K extends keyof OperationsSettings>(k: K, x: OperationsSettings[K]) => setV((p) => ({ ...p, [k]: x }));
  const save = useMutation({ mutationFn: () => unwrap(saveOperationsSettingsAction(v)), onSuccess: () => { toast.success("Saved"); router.refresh(); }, onError });
  const num = (k: "ackMinutes" | "qaSharePct" | "qaMinPerClient" | "digestHour") => (e: React.ChangeEvent<HTMLInputElement>) => set(k, Number(e.target.value) || 0);
  return (
    <div className="grid gap-3 sm:grid-cols-3">
      <div className="grid gap-1">
        <Label htmlFor="ops-sev" className="text-xs">Page on-call for open cases at</Label>
        <NativeSelect id="ops-sev" className="h-8 text-xs" value={v.pageSeverity} onChange={(e) => set("pageSeverity", e.target.value as OperationsSettings["pageSeverity"])}>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High and above</option>
          <option value="MEDIUM">Medium and above</option>
        </NativeSelect>
      </div>
      <div className="grid gap-1"><Label htmlFor="ops-ack" className="text-xs">Minutes before the next person is paged</Label><Input id="ops-ack" type="number" min={2} max={120} className="h-8 text-xs" value={v.ackMinutes} onChange={num("ackMinutes")} /></div>
      <div className="grid gap-1"><Label htmlFor="ops-tz" className="text-xs">Time zone (for the digest)</Label><Input id="ops-tz" className="h-8 text-xs" value={v.timeZone} onChange={(e) => set("timeZone", e.target.value)} /></div>
      <div className="grid gap-1"><Label htmlFor="ops-qa" className="text-xs">QA: share of AI-handled cases reviewed (%)</Label><Input id="ops-qa" type="number" min={1} max={100} className="h-8 text-xs" value={v.qaSharePct} onChange={num("qaSharePct")} /></div>
      <div className="grid gap-1"><Label htmlFor="ops-qamin" className="text-xs">QA: at least this many per client a week</Label><Input id="ops-qamin" type="number" min={0} max={50} className="h-8 text-xs" value={v.qaMinPerClient} onChange={num("qaMinPerClient")} /></div>
      <div className="grid gap-1"><Label htmlFor="ops-hour" className="text-xs">Daily digest at (hour, 0–23)</Label><Input id="ops-hour" type="number" min={0} max={23} className="h-8 text-xs" value={v.digestHour} onChange={num("digestHour")} /></div>
      <div className="sm:col-span-3"><Button size="sm" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save</Button></div>
    </div>
  );
}
