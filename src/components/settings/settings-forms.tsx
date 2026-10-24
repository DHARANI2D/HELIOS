"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { FlaskConical, KeyRound, Loader2, Save, ShieldCheck, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { saveCompanyAction, saveForensicsSettingsAction, savePlatformSecretAction, setEnvironmentAction } from "@/app/(app)/settings/actions";
import type { CompanyProfile } from "@/lib/settings";
import type { SecretStatus } from "@/lib/platform-secrets";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

function useSave<T>(fn: (v: T) => Promise<unknown>, done: string) {
  const router = useRouter();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      toast.success(done);
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
}

const COMPANY_FIELDS: Array<{ key: keyof CompanyProfile; label: string; hint?: string; wide?: boolean; long?: boolean; type?: string }> = [
  { key: "name", label: "Company name", hint: "Shown to clients and on every quote and report" },
  { key: "legalName", label: "Legal name" },
  { key: "email", label: "SOC contact email", type: "email" },
  { key: "phone", label: "SOC phone" },
  { key: "website", label: "Website" },
  { key: "taxId", label: "Tax / VAT number" },
  { key: "address", label: "Address", wide: true, long: true },
  { key: "quoteTerms", label: "Quote terms", hint: "Printed at the end of every quote PDF", wide: true, long: true },
  { key: "reportFooter", label: "Report footer", hint: "One line at the foot of each report page, e.g. a confidentiality notice", wide: true },
];

export function CompanyForm({ initial, canEdit }: { initial: CompanyProfile; canEdit: boolean }) {
  const [d, setD] = React.useState(initial);
  const save = useSave(() => saveCompanyAction(d), "Company profile saved");
  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-3 sm:grid-cols-2">
        {COMPANY_FIELDS.map((f) => (
          <div key={f.key} className={cn("grid gap-1.5", f.wide && "sm:col-span-2")}>
            <Label htmlFor={`company-${f.key}`}>{f.label}</Label>
            {f.long ? (
              <Textarea id={`company-${f.key}`} value={d[f.key]} onChange={(e) => setD({ ...d, [f.key]: e.target.value })} disabled={!canEdit} className="min-h-16" />
            ) : (
              <Input id={`company-${f.key}`} type={f.type ?? "text"} value={d[f.key]} onChange={(e) => setD({ ...d, [f.key]: e.target.value })} disabled={!canEdit} />
            )}
            {f.hint && <p className="text-[11px] text-muted-foreground">{f.hint}</p>}
          </div>
        ))}
      </div>
      {canEdit && (
        <div>
          <Button size="sm" onClick={() => save.mutate(undefined)} disabled={save.isPending}>
            {save.isPending ? <Loader2 className="animate-spin" /> : <Save />}
            Save profile
          </Button>
        </div>
      )}
    </div>
  );
}

export function EnvironmentControl({ environment, testClients, canChange }: { environment: "production" | "test"; testClients: number; canChange: boolean }) {
  const save = useSave((to: "production" | "test") => setEnvironmentAction(to), "Environment changed");
  const test = environment === "test";
  return (
    <div className={cn("flex flex-wrap items-center justify-between gap-3 rounded-lg border p-4", test ? "border-warning/50 bg-warning/10" : "border-success/40 bg-success/5")}>
      <div className="flex items-start gap-3">
        {test ? <FlaskConical className="mt-0.5 size-5" /> : <ShieldCheck className="mt-0.5 size-5 text-success-ink" />}
        <div>
          <p className="text-sm font-semibold">{test ? "Test environment" : "Production"}</p>
          <p className="max-w-xl text-xs text-muted-foreground">
            {test
              ? "Every page carries a test-environment banner, and test clients count in commercial figures. Switch to production once this database serves real clients."
              : `Real clients and real data.${testClients ? ` ${testClients} test client${testClients === 1 ? " is" : "s are"} badged and left out of commercial figures.` : ""}`}
          </p>
        </div>
      </div>
      {canChange ? (
        <Button size="sm" variant="outline" onClick={() => save.mutate(test ? "production" : "test")} disabled={save.isPending}>
          {save.isPending && <Loader2 className="animate-spin" />}
          {test ? "Switch to production" : "Mark as test environment"}
        </Button>
      ) : (
        <p className="text-[11px] text-muted-foreground">Only a platform admin can change this.</p>
      )}
    </div>
  );
}

export interface SecretRow {
  name: string;
  label: string;
  help: string;
  env: string;
  status: SecretStatus;
}

function SecretField({ row, canEdit }: { row: SecretRow; canEdit: boolean }) {
  const [value, setValue] = React.useState("");
  const save = useSave((v: string | null) => savePlatformSecretAction(row.name, v), "Saved");
  const { source, last4 } = row.status;
  return (
    <div className="grid gap-2 rounded-lg border p-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)] md:items-center">
      <div>
        <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
          <KeyRound className="size-3.5 text-muted-foreground" /> {row.label}
          {source === "stored" && <Badge variant="success">stored · …{last4}</Badge>}
          {source === "environment" && <Badge variant="info">from {row.env}</Badge>}
          {!source && <Badge variant="soft">not set</Badge>}
        </p>
        <p className="text-xs text-muted-foreground">{row.help}</p>
      </div>
      {canEdit && (
        <div className="flex gap-2">
          <Input
            type="password"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={source === "stored" ? "Enter a new value to replace it" : source === "environment" ? `Overrides ${row.env}` : "Paste the key"}
            autoComplete="off"
            aria-label={row.label}
          />
          <Button
            size="sm"
            onClick={() => save.mutate(value, { onSuccess: () => setValue("") })}
            disabled={save.isPending || value.trim().length < 8}
          >
            {save.isPending ? <Loader2 className="animate-spin" /> : <Save />}
            Save
          </Button>
          {source === "stored" && (
            <Button size="sm" variant="ghost" onClick={() => save.mutate(null)} disabled={save.isPending} aria-label={`Remove stored ${row.label}`}>
              <Trash2 />
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

export function SecretsPanel({ rows, canEdit }: { rows: SecretRow[]; canEdit: boolean }) {
  return (
    <div className="flex flex-col gap-3">
      {rows.map((r) => (
        <SecretField key={r.name} row={r} canEdit={canEdit} />
      ))}
    </div>
  );
}

export function ForensicsSettingsForm({ thresholds, allowDomains, builtIn, canEdit }: { thresholds: { malicious: number; suspicious: number }; allowDomains: string[]; builtIn: string[]; canEdit: boolean }) {
  const [malicious, setMalicious] = React.useState(thresholds.malicious);
  const [suspicious, setSuspicious] = React.useState(thresholds.suspicious);
  const [domains, setDomains] = React.useState(allowDomains.join("\n"));
  const save = useSave(
    () => saveForensicsSettingsAction({ thresholds: { malicious, suspicious }, allowDomains: domains.split(/[\s,]+/).filter(Boolean) }),
    "Forensics settings saved",
  );
  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="grid gap-1.5">
          <Label htmlFor="th-suspicious">Suspicious at score</Label>
          <Input id="th-suspicious" type="number" min={1} max={499} value={suspicious} onChange={(e) => setSuspicious(Number(e.target.value))} disabled={!canEdit} />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="th-malicious">Malicious at score</Label>
          <Input id="th-malicious" type="number" min={2} max={500} value={malicious} onChange={(e) => setMalicious(Number(e.target.value))} disabled={!canEdit} />
        </div>
        <p className="text-[11px] text-muted-foreground sm:col-span-2">
          A submission&apos;s verdict comes from its total score across header, content, attachment, sandbox, intel and sender checks. The defaults (31 and 71) are desas&apos;s.
        </p>
        <div className="grid gap-1.5 sm:col-span-2">
          <Label htmlFor="allow-domains">Trusted link domains</Label>
          <Textarea id="allow-domains" value={domains} onChange={(e) => setDomains(e.target.value)} disabled={!canEdit} className="min-h-24 font-mono text-xs" aria-describedby="allow-domains-hint" />
          <p id="allow-domains-hint" className="text-[11px] text-muted-foreground">
            One per line. Links to these domains (and their subdomains) are never analyzed or detonated. Always trusted: {builtIn.join(", ")}.
          </p>
        </div>
      </div>
      {canEdit && (
        <div>
          <Button size="sm" onClick={() => save.mutate(undefined)} disabled={save.isPending || suspicious >= malicious}>
            {save.isPending ? <Loader2 className="animate-spin" /> : <Save />}
            Save forensics settings
          </Button>
        </div>
      )}
    </div>
  );
}
