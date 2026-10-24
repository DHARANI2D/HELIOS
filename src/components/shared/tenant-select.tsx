import { Building2 } from "lucide-react";

import { cn } from "@/lib/utils";

interface TenantSelectProps {
  tenants: Array<{ id: string; name: string }>;
  name?: string;
  defaultValue?: string | null;
  value?: string;
  onChange?: (value: string) => void;
  className?: string;
  id?: string;
}

// Plain <select> so it works in server-rendered GET forms and client forms alike.
export function TenantSelect({ tenants, name = "tenantId", defaultValue, value, onChange, className, id }: TenantSelectProps) {
  return (
    <label className={cn("relative flex items-center", className)}>
      <span className="sr-only">Client</span>
      <Building2 className="pointer-events-none absolute left-2.5 size-3.5 text-muted-foreground" />
      <select
        id={id}
        name={name}
        {...(value !== undefined ? { value, onChange: (e) => onChange?.(e.target.value) } : { defaultValue: defaultValue ?? "none" })}
        className="border-input dark:bg-input/30 h-9 w-full rounded-md border bg-transparent pl-8 pr-2.5 text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
      >
        <option value="none">Internal / unassigned</option>
        {tenants.map((t) => (
          <option key={t.id} value={t.id}>
            {t.name}
          </option>
        ))}
      </select>
    </label>
  );
}
