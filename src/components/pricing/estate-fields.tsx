"use client";

import { Cloud, Code2, Factory, KeyRound, Network } from "lucide-react";

import { COMPANY_TYPES, DELIVERY, ENVIRONMENTS, ESTATE_FIELDS, INDUSTRIES, MATURITY, type Estate, type OrgContext } from "@/lib/assets/estate";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";

const GROUPS: Array<{ title: string; icon: typeof Cloud; keys: Array<keyof Estate> }> = [
  { title: "Cloud & SaaS", icon: Cloud, keys: ["cloudAccounts", "cloudWorkloads", "saasApps"] },
  { title: "Network", icon: Network, keys: ["networkDevices"] },
  { title: "Identities", icon: KeyRound, keys: ["privilegedAccounts"] },
  { title: "IoT & OT", icon: Factory, keys: ["iotDevices", "otDevices"] },
  { title: "Applications & code", icon: Code2, keys: ["internetApps", "developers"] },
];

// Counts for the attack surface beyond computers, servers and phones.
export function EstateFields({ estate, onChange, className }: { estate: Estate; onChange: (e: Estate) => void; className?: string }) {
  return (
    <div className={cn("grid gap-4 sm:grid-cols-2", className)}>
      {GROUPS.map((g) => (
        <fieldset key={g.title} className="grid content-start gap-2 rounded-lg border p-3">
          <legend className="flex items-center gap-1.5 px-1 text-xs font-medium"><g.icon className="size-3.5 text-muted-foreground" /> {g.title}</legend>
          {g.keys.map((key) => {
            const f = ESTATE_FIELDS.find((x) => x.key === key)!;
            const id = `estate-${key}`;
            return (
              <div key={key} className="grid gap-1">
                <Label htmlFor={id} className="text-xs">{f.label}</Label>
                <Input id={id} type="number" min={0} inputMode="numeric" value={estate[key]} onChange={(e) => onChange({ ...estate, [key]: Math.max(0, Math.round(Number(e.target.value) || 0)) })} className="h-8 tabular" aria-describedby={`${id}-hint`} />
                <p id={`${id}-hint`} className="text-[11px] text-muted-foreground">{f.hint}</p>
              </div>
            );
          })}
        </fieldset>
      ))}
    </div>
  );
}

function Choice<K extends string>({ label, options, value, onChange, allowEmpty = true }: { label: string; options: Record<K, string>; value: K | null; onChange: (v: K | null) => void; allowEmpty?: boolean }) {
  const keys = Object.keys(options) as K[];
  return (
    <div className="grid content-start gap-1.5">
      <p className="text-xs font-medium">{label}</p>
      <div role="radiogroup" aria-label={label} className="flex flex-wrap gap-1.5">
        {keys.map((k) => (
          <button
            key={k}
            type="button"
            role="radio"
            aria-checked={value === k}
            onClick={() => onChange(value === k && allowEmpty ? null : k)}
            className={cn("rounded-full border px-3 py-1 text-xs transition-colors hover:bg-accent", value === k && "border-primary bg-primary text-primary-foreground hover:bg-primary/90")}
          >
            {options[k]}
          </button>
        ))}
      </div>
    </div>
  );
}

// "Select the company's environment so we can define the scope and
// architecture": the questions the solution design starts from.
export function OrgContextFields({ context, onChange }: { context: OrgContext; onChange: (c: OrgContext) => void }) {
  return (
    <div className="grid gap-4">
      <div className="grid gap-4 md:grid-cols-2">
        <Choice label="Company type" options={COMPANY_TYPES} value={context.companyType} onChange={(v) => onChange({ ...context, companyType: v })} />
        <div className="grid content-start gap-1.5">
          <Label htmlFor="org-industry" className="text-xs font-medium">Industry</Label>
          <NativeSelect id="org-industry" value={context.industry} onChange={(e) => onChange({ ...context, industry: e.target.value as OrgContext["industry"] })} className="h-8 text-sm">
            {(Object.keys(INDUSTRIES) as Array<OrgContext["industry"]>).map((k) => <option key={k} value={k}>{INDUSTRIES[k]}</option>)}
          </NativeSelect>
        </div>
      </div>
      <Choice label="IT environment" options={ENVIRONMENTS} value={context.environment} onChange={(v) => onChange({ ...context, environment: v })} />
      <Choice label="What's being delivered" options={DELIVERY} value={context.delivery} onChange={(v) => onChange({ ...context, delivery: v })} />
      <Choice label="Existing security maturity" options={MATURITY} value={context.maturity} onChange={(v) => onChange({ ...context, maturity: v })} />
    </div>
  );
}
