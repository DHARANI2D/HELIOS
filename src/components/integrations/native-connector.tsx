"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Cable, Loader2, PlugZap, Save } from "lucide-react";
import { toast } from "sonner";

import { saveNativeConnectorAction, testNativeConnectorAction } from "@/app/(app)/integrations/actions";
import type { ConnectorInfo } from "@/lib/connectors/registry";
import { ACTION_LABEL } from "@/lib/response/labels";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { unwrap } from "@/lib/action-result";

interface Props {
  integrationId: string;
  name: string;
  info: ConnectorInfo;
  on: boolean;
  mode: "live" | "dry_run";
  values: Record<string, string>; // non-secret settings
  secretsSet: string[]; // which secret fields have a stored value
  credentialExpiresAt: string;
  canManage: boolean;
}

export function NativeConnectorBadge({ on, mode }: { on: boolean; mode: "live" | "dry_run" }) {
  if (!on) return null;
  return <Badge variant={mode === "live" ? "success" : "warning"} className="text-[10px]">native · {mode === "live" ? "live" : "dry run"}</Badge>;
}

export function NativeConnectorButton(props: Props) {
  const router = useRouter();
  const [open, setOpen] = React.useState(false);
  const [state, setState] = React.useState(props.on ? props.mode : "off");
  const [values, setValues] = React.useState<Record<string, string>>(props.values);
  const [expires, setExpires] = React.useState(props.credentialExpiresAt);
  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed");
  const save = useMutation({
    mutationFn: () => unwrap(saveNativeConnectorAction(props.integrationId, { on: state !== "off", mode: state === "live" ? "live" : "dry_run", values, credentialExpiresAt: expires })),
    onSuccess: () => {
      toast.success(state === "off" ? "Native connector switched off" : state === "live" ? "Native connector is live" : "Native connector in dry run: it checks targets and changes nothing");
      router.refresh();
    },
    onError,
  });
  const test = useMutation({
    mutationFn: () => unwrap(testNativeConnectorAction(props.integrationId)),
    onSuccess: (r) => {
      if (r.ok) toast.success(r.message);
      else toast.error(r.message);
      router.refresh();
    },
    onError,
  });
  if (!props.canManage) return <NativeConnectorBadge on={props.on} mode={props.mode} />;
  return (
    <>
      <Button size="sm" variant="ghost" className="h-7" onClick={() => setOpen(true)} title={`Call ${props.info.label} directly`}>
        <Cable /> {props.on ? (props.mode === "live" ? "Native · live" : "Native · dry run") : "Native connector"}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{props.info.label} connector</DialogTitle>
            <DialogDescription>
              HELIOS calls {props.info.label} with the client&apos;s own least-privilege credentials for: {props.info.actions.map((a) => ACTION_LABEL[a].toLowerCase()).join(", ")}. An action only counts once {props.info.label} confirms it.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="nc-mode">Mode</Label>
              <NativeSelect id="nc-mode" value={state} onChange={(e) => setState(e.target.value as typeof state)}>
                <option value="off">Off (use the response webhook or do it by hand)</option>
                <option value="dry_run">Dry run: check targets, change nothing</option>
                <option value="live">Live: carry out approved actions</option>
              </NativeSelect>
            </div>
            {props.info.fields.map((f) => (
              <div key={f.key} className="grid gap-1.5">
                <Label htmlFor={`nc-${f.key}`}>{f.label}{f.required ? "" : " (optional)"}</Label>
                <Input
                  id={`nc-${f.key}`}
                  type={f.secret ? "password" : "text"}
                  autoComplete="off"
                  value={values[f.key] ?? ""}
                  placeholder={f.secret && props.secretsSet.includes(f.key) ? "•••••••• stored — leave blank to keep" : f.placeholder}
                  onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}
                />
                {f.hint && <p className="text-[11px] text-muted-foreground">{f.hint}</p>}
              </div>
            ))}
            <div className="grid gap-1.5">
              <Label htmlFor="nc-exp">Credential expires (optional)</Label>
              <Input id="nc-exp" type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />
              <p className="text-[11px] text-muted-foreground">The SOC and the client&apos;s admins are reminded two weeks before.</p>
            </div>
            <p className="text-[11px] text-muted-foreground">Written against: {props.info.docs}. Try it in dry run against a lab tenant before going live.</p>
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => test.mutate()} disabled={test.isPending || !props.on} title={props.on ? undefined : "Save it in dry run or live first"}>
              {test.isPending ? <Loader2 className="animate-spin" /> : <PlugZap />} Test connection
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
