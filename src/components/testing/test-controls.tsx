"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Check, Loader2, Play, RefreshCw, ShieldCheck, Square, Upload } from "lucide-react";
import { toast } from "sonner";

import { authoriseTestAction, closeTestAction, importResultsAction, requestTestAction, retestAction, setFindingStatusAction, verifyTestAction } from "@/app/(app)/testing/actions";
import { unwrap } from "@/lib/action-result";
import type { CheckKey } from "@/lib/testing/exposure";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { NativeSelect } from "@/components/ui/native-select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";

const toLocalInput = (d: Date) => new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);

export function RequestTestForm({ tenants, isClient, checks }: { tenants: Array<{ id: string; name: string }>; isClient: boolean; checks: Record<string, string> }) {
  const router = useRouter();
  const [open, setOpen] = React.useState(false);
  const [form, setForm] = React.useState(() => {
    // Tomorrow on the hour, for a week.
    const start = new Date(Date.now() + 86_400_000);
    start.setMinutes(0, 0, 0);
    return {
      tenantId: tenants[0]?.id ?? "",
      title: "",
      targets: "",
      checks: Object.keys(checks) as CheckKey[],
      rulesOfEngagement: "Contact during the test: \nOut of bounds: \nAvoid these times: ",
      windowStart: toLocalInput(start),
      windowEnd: toLocalInput(new Date(start.getTime() + 7 * 86_400_000)),
    };
  });
  const set = (k: keyof typeof form, v: unknown) => setForm((f) => ({ ...f, [k]: v }));
  const submit = useMutation({
    mutationFn: () => unwrap(requestTestAction({ ...form, windowStart: new Date(form.windowStart).toISOString(), windowEnd: new Date(form.windowEnd).toISOString() })),
    onSuccess: ({ id }) => {
      toast.success("Requested. Next: verify the targets and authorise it.");
      setOpen(false);
      router.push(`/testing/${id}`);
    },
    onError: (err: Error) => toast.error(err.message),
  });
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button><ShieldCheck /> Request a test</Button>
      </DialogTrigger>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Request a security test</DialogTitle>
          <DialogDescription>
            HELIOS checks only targets {isClient ? "you prove you" : "the client proves it"} control{isClient ? "" : "s"}, only inside the window, and only once the client&apos;s admin and a HELIOS approver have both authorised it.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          {!isClient && (
            <div className="grid gap-1.5">
              <Label htmlFor="t-tenant">Client</Label>
              <NativeSelect id="t-tenant" value={form.tenantId} onChange={(e) => set("tenantId", e.target.value)}>
                {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
              </NativeSelect>
            </div>
          )}
          <div className="grid gap-1.5">
            <Label htmlFor="t-title">Name</Label>
            <Input id="t-title" value={form.title} onChange={(e) => set("title", e.target.value)} placeholder="Quarterly external exposure check" maxLength={200} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="t-targets">Targets</Label>
            <Textarea id="t-targets" value={form.targets} onChange={(e) => set("targets", e.target.value)} rows={3} className="font-mono text-xs" placeholder={"example.com\nvpn.example.com\n203.0.113.10\nhttps://portal.example.com"} />
            <p className="text-xs text-muted-foreground">Domains, host names, public IP addresses or URLs, up to 25. No ranges, no private addresses.</p>
          </div>
          <div className="grid gap-1.5">
            <Label>Checks</Label>
            {Object.entries(checks).map(([k, label]) => (
              <label key={k} className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={form.checks.includes(k as CheckKey)} onChange={(e) => set("checks", e.target.checked ? [...form.checks, k as CheckKey] : form.checks.filter((c) => c !== k))} />
                {label}
              </label>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="t-start">Window starts</Label>
              <Input id="t-start" type="datetime-local" value={form.windowStart} onChange={(e) => set("windowStart", e.target.value)} />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="t-end">Window ends</Label>
              <Input id="t-end" type="datetime-local" value={form.windowEnd} onChange={(e) => set("windowEnd", e.target.value)} />
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="t-roe">Rules of engagement</Label>
            <Textarea id="t-roe" value={form.rulesOfEngagement} onChange={(e) => set("rulesOfEngagement", e.target.value)} rows={4} />
          </div>
        </div>
        <DialogFooter>
          <Button onClick={() => submit.mutate()} disabled={submit.isPending || !form.title.trim() || !form.targets.trim()}>
            {submit.isPending && <Loader2 className="animate-spin" />} Request
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function useAction<T>(fn: () => Promise<T>, ok: (v: T) => string) {
  const router = useRouter();
  return useMutation({
    mutationFn: fn,
    onSuccess: (v) => {
      toast.success(ok(v));
      router.refresh();
    },
    onError: (err: Error) => toast.error(err.message),
  });
}

export function VerifyButton({ testId }: { testId: string }) {
  const m = useAction(() => unwrap(verifyTestAction(testId)), (r) => `${r.verified} of ${r.total} target(s) verified`);
  return (
    <Button size="sm" variant="outline" onClick={() => m.mutate()} disabled={m.isPending}>
      {m.isPending ? <Loader2 className="animate-spin" /> : <RefreshCw />} Check DNS now
    </Button>
  );
}

export function AuthoriseButton({ testId, attestation }: { testId: string; attestation: string | null }) {
  const [attest, setAttest] = React.useState(false);
  const m = useAction(() => unwrap(authoriseTestAction(testId, attest)), (r) => (r.status === "authorised" ? "Authorised: it runs on its own when the window opens" : "Authorised; waiting for the other side"));
  return (
    <div className="flex flex-col gap-2">
      {attestation && (
        <label className="flex items-start gap-2 text-xs">
          <input type="checkbox" className="mt-0.5" checked={attest} onChange={(e) => setAttest(e.target.checked)} />
          <span>{attestation}</span>
        </label>
      )}
      <div>
        <Button size="sm" onClick={() => m.mutate()} disabled={m.isPending || (!!attestation && !attest)}>
          {m.isPending ? <Loader2 className="animate-spin" /> : <Check />} Authorise
        </Button>
      </div>
    </div>
  );
}

export function StopButton({ testId, label }: { testId: string; label: string }) {
  const [reason, setReason] = React.useState("");
  const [open, setOpen] = React.useState(false);
  const m = useAction(() => unwrap(closeTestAction(testId, reason)), () => "Done");
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline"><Square /> {label}</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{label}</DialogTitle>
          <DialogDescription>Either side can stop a test at any time. A running test stops before its next probe.</DialogDescription>
        </DialogHeader>
        <Textarea value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why" rows={3} maxLength={1000} />
        <DialogFooter>
          <Button variant="destructive" onClick={() => m.mutate()} disabled={m.isPending || !reason.trim()}>
            {m.isPending && <Loader2 className="animate-spin" />} {label}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function RetestButton({ testId }: { testId: string }) {
  const m = useAction(() => unwrap(retestAction(testId)), () => "Queued: HELIOS runs it within a minute");
  return (
    <Button size="sm" variant="outline" onClick={() => m.mutate()} disabled={m.isPending}>
      {m.isPending ? <Loader2 className="animate-spin" /> : <Play />} Run again now
    </Button>
  );
}

export function FindingStatus({ testId, findingId, status, canAccept }: { testId: string; findingId: string; status: string; canAccept: boolean }) {
  const [note, setNote] = React.useState("");
  const [next, setNext] = React.useState<string | null>(null);
  const m = useAction(() => unwrap(setFindingStatusAction(testId, findingId, next as "open" | "fixed" | "accepted", note)), () => "Updated");
  if (next) {
    return (
      <div className="flex min-w-56 flex-col gap-1">
        <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder={next === "accepted" ? "Why the risk is accepted" : "Note (optional)"} className="h-7 text-xs" maxLength={1000} />
        <div className="flex gap-1">
          <Button size="sm" className="h-7" onClick={() => m.mutate()} disabled={m.isPending || (next === "accepted" && !note.trim())}>Save</Button>
          <Button size="sm" variant="ghost" className="h-7" onClick={() => setNext(null)}>Cancel</Button>
        </div>
      </div>
    );
  }
  return (
    <NativeSelect value={status} onChange={(e) => setNext(e.target.value)} className="h-7 w-28 text-xs" aria-label="Status">
      <option value="open">Open</option>
      <option value="fixed">Fixed</option>
      {(canAccept || status === "accepted") && <option value="accepted">Accepted</option>}
    </NativeSelect>
  );
}

export function ImportForm({ testId, tools }: { testId: string; tools: Record<string, string> }) {
  const [tool, setTool] = React.useState("");
  const [file, setFile] = React.useState<File | null>(null);
  const m = useAction(
    async () => {
      if (!file) throw new Error("Pick the report file");
      if (file.size > 20 * 1024 * 1024) throw new Error("The report is over 20 MB; split it by host");
      return unwrap(importResultsAction(testId, { name: file.name, text: await file.text(), tool: tool || null }));
    },
    (r) => `${r.kept} finding(s) added${r.outOfScope ? `; ${r.outOfScope} outside this test's scope left out` : ""}`,
  );
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Input type="file" accept=".nessus,.xml,.json,.jsonl" className="max-w-72" onChange={(e) => setFile(e.target.files?.[0] ?? null)} aria-label="Scanner report" />
      <NativeSelect value={tool} onChange={(e) => setTool(e.target.value)} className="w-56" aria-label="Scanner">
        <option value="">Detect the scanner</option>
        {Object.entries(tools).map(([k, label]) => <option key={k} value={k}>{label}</option>)}
      </NativeSelect>
      <Button size="sm" onClick={() => m.mutate()} disabled={m.isPending || !file}>
        {m.isPending ? <Loader2 className="animate-spin" /> : <Upload />} Add results
      </Button>
    </div>
  );
}
