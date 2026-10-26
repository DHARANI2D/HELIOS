"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { CheckCircle2, FlaskConical, Loader2, Upload, XCircle } from "lucide-react";
import { toast } from "sonner";

import { checkRulesAction, importRulesAction } from "@/app/(app)/detections/actions";
import type { RuleCheck } from "@/lib/detections/service";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";

export function SigmaImport({ tenants }: { tenants: Array<{ id: string; name: string }> }) {
  const router = useRouter();
  const [text, setText] = React.useState("");
  const [tenantId, setTenantId] = React.useState("");
  const [checks, setChecks] = React.useState<RuleCheck[] | null>(null);
  const onError = (e: Error) => toast.error(e.message);
  const check = useMutation({ mutationFn: () => checkRulesAction(text, tenantId || null), onSuccess: setChecks, onError });
  const save = useMutation({
    mutationFn: () => importRulesAction(text, tenantId || null),
    onSuccess: (results) => {
      const ok = results.filter((r) => r.ok).length;
      toast.success(`${ok} rule${ok === 1 ? "" : "s"} imported in testing${results.length > ok ? `; ${results.length - ok} refused` : ""}`);
      setText("");
      setChecks(null);
      router.refresh();
    },
    onError,
  });
  const anyOk = checks?.some((c) => c.ok);

  return (
    <div className="flex flex-col gap-3">
      <div className="grid gap-1.5">
        <Label htmlFor="sigma-yaml" className="text-xs">Sigma rules (YAML; separate several with ---)</Label>
        <Textarea id="sigma-yaml" rows={10} className="font-mono text-xs" placeholder={"title: Suspicious encoded PowerShell\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\\\powershell.exe'\n    CommandLine|contains: ' -enc '\n  condition: selection\nlevel: high"} value={text} onChange={(e) => { setText(e.target.value); setChecks(null); }} />
      </div>
      <div className="flex flex-wrap items-end gap-2">
        <div className="grid gap-1.5">
          <Label htmlFor="sigma-scope" className="text-xs">For</Label>
          <NativeSelect id="sigma-scope" className="h-8 w-64 text-xs" value={tenantId} onChange={(e) => { setTenantId(e.target.value); setChecks(null); }}>
            <option value="">Every client</option>
            {tenants.map((t) => <option key={t.id} value={t.id}>{t.name} only</option>)}
          </NativeSelect>
        </div>
        <Button size="sm" variant="outline" disabled={!text.trim() || check.isPending} onClick={() => check.mutate()}>{check.isPending ? <Loader2 className="animate-spin" /> : <FlaskConical />} Check and backtest</Button>
        <Button size="sm" disabled={!anyOk || save.isPending} onClick={() => save.mutate()}>{save.isPending ? <Loader2 className="animate-spin" /> : <Upload />} Import in testing</Button>
      </div>
      {checks && (
        <ul className="flex flex-col gap-2">
          {checks.map((c) => (
            <li key={c.index} className="rounded-md border p-2 text-xs">
              <p className="flex flex-wrap items-center gap-2 font-medium">
                {c.ok ? <CheckCircle2 className="size-4 text-success-ink" /> : <XCircle className="size-4 text-destructive" />}
                {c.title}
                {c.level && <Badge variant="outline">{c.level}</Badge>}
                {c.techniques?.map((t) => <Badge key={t} variant="soft" className="font-mono">{t}</Badge>)}
              </p>
              {c.errors.map((e, i) => <p key={i} className="text-destructive">{e}</p>)}
              {c.warnings.map((w, i) => <p key={i} className="text-warning-ink">{w}</p>)}
              {c.backtest && (
                <div className="mt-1 text-muted-foreground">
                  <p>Backtest: matched {c.backtest.matched.toLocaleString()} of {c.backtest.events.toLocaleString()} events in the last {c.backtest.days} days{c.backtest.matched > 50 ? " — that's a lot: tune it before it goes live" : ""}.</p>
                  {c.backtest.samples.length > 0 && <ul className="mt-1 font-mono text-[11px]">{c.backtest.samples.map((s, i) => <li key={i} className="truncate">{s}</li>)}</ul>}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
