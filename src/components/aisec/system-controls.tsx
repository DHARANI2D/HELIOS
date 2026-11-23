"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Copy, Eye, KeyRound, Loader2, Save, ShieldCheck, Wand2 } from "lucide-react";
import { toast } from "sonner";

import { applyRecommendationsAction, issueKeyAction, revealContentAction, revokeKeyAction, updateProfileAction, verifyReceiptAction } from "@/app/(app)/ai-security/actions";
import { unwrap } from "@/lib/action-result";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";

function useSave<T>(fn: (v: T) => Promise<unknown>, ok: string) {
  const router = useRouter();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      toast.success(ok);
      router.refresh();
    },
    onError: (e: Error) => toast.error(e.message),
  });
}

const copy = (text: string) => navigator.clipboard.writeText(text).then(() => toast.success("Copied"));

export function KeyPanel({ systemId, prefix, canManage }: { systemId: string; prefix: string | null; canManage: boolean }) {
  const router = useRouter();
  const [token, setToken] = React.useState<string | null>(null);
  const issue = useMutation({
    mutationFn: () => unwrap(issueKeyAction(systemId)),
    onSuccess: (r) => {
      setToken(r.token);
      router.refresh();
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const revoke = useSave(() => unwrap(revokeKeyAction(systemId)), "Key revoked: the application can no longer call HELIOS");
  return (
    <div className="flex flex-col gap-2">
      <p className="text-sm">{prefix ? <>Key in use: <code>{prefix}</code></> : "No key yet: the application can't call the guard or the gateway."}</p>
      {token && (
        <div className="flex flex-col gap-1 rounded-md border border-warning/50 bg-warning/5 p-2">
          <p className="text-xs font-medium">Copy it now: it won&apos;t be shown again.</p>
          <div className="flex items-center gap-2">
            <code className="min-w-0 flex-1 truncate text-xs">{token}</code>
            <Button size="icon" variant="ghost" className="size-7" onClick={() => copy(token)} aria-label="Copy key"><Copy /></Button>
          </div>
        </div>
      )}
      {canManage && (
        <div className="flex gap-2">
          <Button size="sm" variant={prefix ? "outline" : "default"} onClick={() => issue.mutate()} disabled={issue.isPending}>{issue.isPending ? <Loader2 className="animate-spin" /> : <KeyRound />} {prefix ? "Rotate the key" : "Issue a key"}</Button>
          {prefix && <Button size="sm" variant="ghost" onClick={() => revoke.mutate(undefined)} disabled={revoke.isPending}>Revoke</Button>}
        </div>
      )}
    </div>
  );
}

export interface EndpointValues {
  endpoint: string | null;
  endpointFormat: string;
  endpointModel: string | null;
  requestTemplate: string | null;
  responsePath: string | null;
  authHeader: string | null;
  hasAuth: boolean;
}

export function EndpointForm({ systemId, values, canManage }: { systemId: string; values: EndpointValues; canManage: boolean }) {
  const [v, setV] = React.useState({ endpoint: values.endpoint ?? "", endpointFormat: values.endpointFormat, endpointModel: values.endpointModel ?? "", requestTemplate: values.requestTemplate ?? "", responsePath: values.responsePath ?? "", authHeader: values.authHeader ?? "", authValue: "" });
  const set = (k: keyof typeof v, x: string) => setV((o) => ({ ...o, [k]: x }));
  const save = useSave(
    () =>
      unwrap(
        updateProfileAction(systemId, {
          endpoint: v.endpoint || null,
          endpointFormat: v.endpointFormat as "openai" | "json",
          endpointModel: v.endpointModel || null,
          requestTemplate: v.endpointFormat === "json" ? v.requestTemplate || null : null,
          responsePath: v.endpointFormat === "json" ? v.responsePath || null : null,
          authHeader: v.authHeader || null,
          ...(v.authValue ? { authValue: v.authValue } : {}),
        }),
      ),
    "Saved",
  );
  const ro = !canManage;
  return (
    <div className="grid gap-2">
      <Label htmlFor="ep" className="text-xs">Chat endpoint (https)</Label>
      <Input id="ep" disabled={ro} value={v.endpoint} onChange={(e) => set("endpoint", e.target.value)} placeholder="https://bot.example.com/v1/chat/completions" className="font-mono text-xs" />
      <div className="grid grid-cols-2 gap-2">
        <div className="grid gap-1">
          <Label className="text-xs">It speaks</Label>
          <NativeSelect disabled={ro} value={v.endpointFormat} onChange={(e) => set("endpointFormat", e.target.value)} className="h-8 text-xs">
            <option value="openai">OpenAI chat completions</option>
            <option value="json">Its own JSON</option>
          </NativeSelect>
        </div>
        {v.endpointFormat === "openai" ? (
          <div className="grid gap-1">
            <Label className="text-xs">Model name to send</Label>
            <Input disabled={ro} value={v.endpointModel} onChange={(e) => set("endpointModel", e.target.value)} placeholder="default" className="h-8 text-xs" />
          </div>
        ) : (
          <div className="grid gap-1">
            <Label className="text-xs">Where the answer is</Label>
            <Input disabled={ro} value={v.responsePath} onChange={(e) => set("responsePath", e.target.value)} placeholder="reply.text" className="h-8 font-mono text-xs" />
          </div>
        )}
      </div>
      {v.endpointFormat === "json" && (
        <>
          <Label className="text-xs">Request body ({"{{prompt}}"} where the message goes)</Label>
          <Textarea disabled={ro} rows={2} value={v.requestTemplate} onChange={(e) => set("requestTemplate", e.target.value)} placeholder={'{"message": "{{prompt}}", "session": "helios-red-team"}'} className="font-mono text-xs" />
        </>
      )}
      <div className="grid grid-cols-2 gap-2">
        <div className="grid gap-1">
          <Label className="text-xs">Header it needs (optional)</Label>
          <Input disabled={ro} value={v.authHeader} onChange={(e) => set("authHeader", e.target.value)} placeholder="Authorization" className="h-8 text-xs" />
        </div>
        <div className="grid gap-1">
          <Label className="text-xs">Its value {values.hasAuth ? "(saved; type to replace)" : ""}</Label>
          <Input disabled={ro} type="password" value={v.authValue} onChange={(e) => set("authValue", e.target.value)} placeholder={values.hasAuth ? "••••••••" : "Bearer …"} className="h-8 text-xs" />
        </div>
      </div>
      {canManage && <Button size="sm" className="w-fit" onClick={() => save.mutate(undefined)} disabled={save.isPending}>{save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save</Button>}
    </div>
  );
}

export function GatewayForm({ systemId, values, canManage }: { systemId: string; values: { upstreamUrl: string | null; upstreamModel: string | null; hasKey: boolean; privacyMode: boolean; retainContent: boolean }; canManage: boolean }) {
  const [v, setV] = React.useState({ upstreamUrl: values.upstreamUrl ?? "", upstreamModel: values.upstreamModel ?? "", upstreamKey: "", privacyMode: values.privacyMode, retainContent: values.retainContent });
  const save = useSave(() => unwrap(updateProfileAction(systemId, { upstreamUrl: v.upstreamUrl || null, upstreamModel: v.upstreamModel || null, privacyMode: v.privacyMode, retainContent: v.retainContent, ...(v.upstreamKey ? { upstreamKey: v.upstreamKey } : {}) })), "Saved");
  const ro = !canManage;
  return (
    <div className="grid gap-2">
      <div className="grid grid-cols-2 gap-2">
        <div className="grid gap-1">
          <Label className="text-xs">Model provider (OpenAI-compatible base URL)</Label>
          <Input disabled={ro} value={v.upstreamUrl} onChange={(e) => setV({ ...v, upstreamUrl: e.target.value })} placeholder="https://api.openai.com/v1" className="h-8 font-mono text-xs" />
        </div>
        <div className="grid gap-1">
          <Label className="text-xs">Default model</Label>
          <Input disabled={ro} value={v.upstreamModel} onChange={(e) => setV({ ...v, upstreamModel: e.target.value })} placeholder="gpt-4.1-mini" className="h-8 text-xs" />
        </div>
      </div>
      <div className="grid gap-1">
        <Label className="text-xs">Provider API key {values.hasKey ? "(saved, sealed with the client's key; type to replace)" : ""}</Label>
        <Input disabled={ro} type="password" value={v.upstreamKey} onChange={(e) => setV({ ...v, upstreamKey: e.target.value })} placeholder={values.hasKey ? "••••••••" : "sk-…"} className="h-8 text-xs" />
      </div>
      <label className="flex items-center justify-between gap-3 text-sm">
        <span>Privacy mode: mask personal data before it reaches the provider, put it back in the answer</span>
        <Switch disabled={ro} checked={v.privacyMode} onCheckedChange={(x) => setV({ ...v, privacyMode: x })} />
      </label>
      <label className="flex items-center justify-between gap-3 text-sm">
        <span>Keep prompts and answers, sealed with the client&apos;s key (off: only verdicts are kept)</span>
        <Switch disabled={ro} checked={v.retainContent} onCheckedChange={(x) => setV({ ...v, retainContent: x })} />
      </label>
      {canManage && <Button size="sm" className="w-fit" onClick={() => save.mutate(undefined)} disabled={save.isPending}>{save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save</Button>}
    </div>
  );
}

export function StatusSelect({ systemId, status, canManage }: { systemId: string; status: string; canManage: boolean }) {
  const save = useSave((s: string) => unwrap(updateProfileAction(systemId, { status: s as "active" })), "Status changed");
  return (
    <NativeSelect value={status} disabled={!canManage || save.isPending} onChange={(e) => save.mutate(e.target.value)} className="h-8 w-32 text-xs" aria-label="Status">
      <option value="active">Active</option>
      <option value="paused">Paused</option>
      <option value="retired">Retired</option>
    </NativeSelect>
  );
}

export function Recommendations({ systemId, items, canManage }: { systemId: string; items: Array<{ id: string; title: string; why: string }>; canManage: boolean }) {
  const [picked, setPicked] = React.useState<string[]>(items.map((i) => i.id));
  const apply = useSave(() => unwrap(applyRecommendationsAction(systemId, picked)), "Protections switched on (a new policy version)");
  if (!items.length) return <p className="flex items-start gap-2 text-sm text-muted-foreground"><ShieldCheck className="mt-0.5 size-4 shrink-0" /> <span>The policy already has the protections these findings call for. They only help if the application calls the guard or sends its model calls through the gateway (see Connect): the red team talks to the application directly, so a finding that stays open after a re-test means it isn&apos;t routed through HELIOS yet, or the application itself needs the fix.</span></p>;
  return (
    <div className="flex flex-col gap-2">
      {items.map((r) => (
        <label key={r.id} className="flex items-start gap-2 text-sm">
          <input type="checkbox" className="mt-1" disabled={!canManage} checked={picked.includes(r.id)} onChange={(e) => setPicked(e.target.checked ? [...picked, r.id] : picked.filter((x) => x !== r.id))} />
          <span>{r.title}<span className="block text-xs text-muted-foreground">{r.why}</span></span>
        </label>
      ))}
      {canManage && <Button size="sm" className="w-fit" onClick={() => apply.mutate(undefined)} disabled={apply.isPending || !picked.length}>{apply.isPending ? <Loader2 className="animate-spin" /> : <Wand2 />} Switch them on</Button>}
    </div>
  );
}

export function RevealContent({ systemId, eventId }: { systemId: string; eventId: string }) {
  const [data, setData] = React.useState<Awaited<ReturnType<typeof revealContentAction>> | null>(null);
  const m = useMutation({ mutationFn: () => unwrap(revealContentAction(systemId, eventId)), onSuccess: (d) => setData(d as never), onError: (e: Error) => toast.error(e.message) });
  return (
    <Dialog onOpenChange={(o) => o && !data && m.mutate()}>
      <DialogTrigger asChild>
        <Button size="icon" variant="ghost" className="size-7" aria-label="Open the kept content"><Eye /></Button>
      </DialogTrigger>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Kept content</DialogTitle>
          <DialogDescription>Sealed with the client&apos;s key; opening it is recorded in the audit log.</DialogDescription>
        </DialogHeader>
        {m.isPending && <Loader2 className="animate-spin" />}
        {data && "stage" in (data as object) && <pre className="max-h-[60vh] overflow-auto rounded-md bg-muted p-3 text-xs whitespace-pre-wrap">{JSON.stringify(data, null, 2)}</pre>}
      </DialogContent>
    </Dialog>
  );
}

export function ReceiptVerifier() {
  const [text, setText] = React.useState("");
  const [result, setResult] = React.useState<{ valid: boolean; reason: string } | null>(null);
  const m = useMutation({ mutationFn: () => unwrap(verifyReceiptAction(text)), onSuccess: setResult, onError: (e: Error) => toast.error(e.message) });
  return (
    <div className="flex flex-col gap-2">
      <Textarea rows={4} value={text} onChange={(e) => { setText(e.target.value); setResult(null); }} placeholder='{"body": {…}, "keyId": "…", "signature": "…"}' className="font-mono text-xs" aria-label="Receipt" />
      <div className="flex items-center gap-2">
        <Button size="sm" variant="outline" onClick={() => m.mutate()} disabled={!text.trim() || m.isPending}>{m.isPending ? <Loader2 className="animate-spin" /> : <ShieldCheck />} Check the signature</Button>
        {result && <span className={`text-xs ${result.valid ? "text-success-ink" : "text-destructive"}`}>{result.reason}</span>}
      </div>
    </div>
  );
}

export function CopyBlock({ text }: { text: string }) {
  return (
    <div className="relative">
      <pre className="overflow-x-auto rounded-md bg-muted p-3 pr-10 text-[11px] leading-relaxed">{text}</pre>
      <Button size="icon" variant="ghost" className="absolute top-1 right-1 size-7" onClick={() => copy(text)} aria-label="Copy"><Copy /></Button>
    </div>
  );
}
