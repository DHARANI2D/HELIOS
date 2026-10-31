"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { CloudDownload, Loader2, PlugZap, Save } from "lucide-react";
import { toast } from "sonner";

import { saveCollectorAction, testCollectorAction } from "@/app/(app)/integrations/actions";
import type { CollectorInfo } from "@/lib/collectors/registry";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { unwrap } from "@/lib/action-result";

export interface StreamState {
  key: string;
  lastSuccessAt: string | null;
  lastError: string | null;
  records: number;
}

interface Props {
  integrationId: string;
  name: string;
  info: CollectorInfo;
  enabled: string[];
  values: Record<string, string>;
  secretsSet: string[];
  streams: StreamState[];
  now: string;
}

const ago = (iso: string | null, now: string) => {
  if (!iso) return "never";
  const m = Math.round((Date.parse(now) - Date.parse(iso)) / 60_000);
  return m < 1 ? "just now" : m < 120 ? `${m} min ago` : `${Math.round(m / 60)} h ago`;
};

export function LogCollectorButton(props: Props) {
  const router = useRouter();
  const [open, setOpen] = React.useState(false);
  const [on, setOn] = React.useState(props.enabled.length > 0);
  const [streams, setStreams] = React.useState<string[]>(props.enabled.length ? props.enabled : props.info.streams.map((s) => s.key));
  const [values, setValues] = React.useState<Record<string, string>>(props.values);
  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed");
  const save = useMutation({
    mutationFn: () => unwrap(saveCollectorAction(props.integrationId, { on, streams, values })),
    onSuccess: () => {
      toast.success(on ? "Collector saved: it starts pulling within a minute" : "Collector switched off");
      router.refresh();
    },
    onError,
  });
  const test = useMutation({
    mutationFn: () => unwrap(testCollectorAction(props.integrationId)),
    onSuccess: (results) => {
      for (const r of results) (r.ok ? toast.success : toast.error)(r.message);
    },
    onError,
  });
  const state = new Map(props.streams.map((s) => [s.key, s]));
  const failing = props.streams.some((s) => s.lastError && props.enabled.includes(s.key));
  return (
    <>
      <Button size="sm" variant="ghost" className="h-7" onClick={() => setOpen(true)} title={`Pull logs from ${props.info.label}`}>
        <CloudDownload /> {props.enabled.length ? `Collecting ${props.enabled.length}` : "Log collector"}
        {failing && <span className="size-1.5 rounded-full bg-destructive" aria-label="a stream is failing" />}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{props.info.label}</DialogTitle>
            <DialogDescription>
              HELIOS polls {props.info.label} with the client&apos;s read-only credentials and queues what it reads. Re-reads are harmless: each event is stored once.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="flex items-center justify-between rounded-md border px-3 py-2">
              <Label htmlFor="lc-on">Collect logs</Label>
              <Switch id="lc-on" checked={on} onCheckedChange={setOn} />
            </div>
            <fieldset className="grid gap-2">
              <legend className="mb-1 text-sm font-medium">Logs</legend>
              {props.info.streams.map((s) => {
                const st = state.get(s.key);
                return (
                  <label key={s.key} className="flex items-start gap-2 text-sm">
                    <input
                      type="checkbox"
                      className="mt-1"
                      checked={streams.includes(s.key)}
                      onChange={(e) => setStreams(e.target.checked ? [...streams, s.key] : streams.filter((k) => k !== s.key))}
                    />
                    <span>
                      {s.label} <span className="text-muted-foreground">· every {s.everyMinutes} min</span>
                      <span className="block text-[11px] text-muted-foreground">Needs: {s.permissions}</span>
                      {st && props.enabled.includes(s.key) && (
                        <span className={st.lastError ? "block text-[11px] text-destructive" : "block text-[11px] text-muted-foreground"}>
                          {st.lastError ? `Failing: ${st.lastError}` : `Last read ${ago(st.lastSuccessAt, props.now)} · ${st.records.toLocaleString()} records so far`}
                        </span>
                      )}
                    </span>
                  </label>
                );
              })}
            </fieldset>
            {props.info.fields.map((f) => (
              <div key={f.key} className="grid gap-1.5">
                <Label htmlFor={`lc-${f.key}`}>{f.label}{f.required ? "" : " (optional)"}</Label>
                {f.key === "serviceAccountKey" ? (
                  <Textarea
                    id={`lc-${f.key}`}
                    rows={3}
                    className="font-mono text-xs"
                    value={values[f.key] ?? ""}
                    placeholder={props.secretsSet.includes(f.key) ? "•••••••• stored — leave blank to keep" : '{"type": "service_account", ...}'}
                    onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}
                  />
                ) : (
                  <Input
                    id={`lc-${f.key}`}
                    type={f.secret ? "password" : "text"}
                    autoComplete="off"
                    value={values[f.key] ?? ""}
                    placeholder={f.secret && props.secretsSet.includes(f.key) ? "•••••••• stored — leave blank to keep" : f.placeholder}
                    onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}
                  />
                )}
                {f.hint && <p className="text-[11px] text-muted-foreground">{f.hint}</p>}
              </div>
            ))}
            <p className="text-[11px] text-muted-foreground">Written against: {props.info.docs}. Check it against a lab tenant before production.</p>
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => test.mutate()} disabled={test.isPending || !props.enabled.length} title={props.enabled.length ? "Reads the last hour; changes nothing" : "Save it first"}>
              {test.isPending ? <Loader2 className="animate-spin" /> : <PlugZap />} Test
            </Button>
            <Button onClick={() => save.mutate()} disabled={save.isPending}>
              {save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
