"use client";

import { Laptop, Server, Smartphone } from "lucide-react";

import { ENDPOINT_TYPES, mixMobile, mixServers, mixWorkstations, type EndpointMix } from "@/lib/pricing/endpoint-mix";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const KIND_ICON = { workstation: Laptop, server: Server, mobile: Smartphone } as const;

// Endpoint counts by OS: what tool suggestions check platform support
// against. Computers and servers are billed; phones only count for MDM.
export function EndpointMixFields({ mix, onChange, className }: { mix: EndpointMix; onChange: (mix: EndpointMix) => void; className?: string }) {
  return (
    <div className={cn("flex flex-col gap-3", className)}>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {ENDPOINT_TYPES.map((t) => {
          const Icon = KIND_ICON[t.kind];
          const id = `mix-${t.key}`;
          return (
            <div key={t.key} className="grid gap-1.5">
              <Label htmlFor={id} className="flex items-center gap-1.5 text-xs">
                <Icon className="size-3.5 text-muted-foreground" /> {t.label}
              </Label>
              <Input
                id={id}
                type="number"
                min={0}
                inputMode="numeric"
                value={mix[t.key]}
                onChange={(e) => onChange({ ...mix, [t.key]: Math.max(0, Math.round(Number(e.target.value) || 0)) })}
                className="tabular"
              />
            </div>
          );
        })}
      </div>
      <p className="text-xs text-muted-foreground">
        <span className="font-medium text-foreground tabular">{(mixWorkstations(mix) + mixServers(mix)).toLocaleString()}</span> endpoints ({mixWorkstations(mix).toLocaleString()} computers,{" "}
        {mixServers(mix).toLocaleString()} servers) are priced per endpoint{mixMobile(mix) ? `; ${mixMobile(mix).toLocaleString()} phones and tablets count only for device management` : ""}.
      </p>
    </div>
  );
}
