"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Search } from "lucide-react";

import { lookupAction, type IndicatorLookup } from "@/app/(app)/threat-intel/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { VerdictBadge } from "@/components/threat-intel/verdict-badge";
import { unwrap } from "@/lib/action-result";

export function LookupForm() {
  const router = useRouter();
  const [value, setValue] = React.useState("");
  const [force, setForce] = React.useState(false);

  const lookup = useMutation({
    mutationFn: () => unwrap(lookupAction(value, force)),
    onSuccess: () => router.refresh(),
  });
  const result: IndicatorLookup | undefined = lookup.data;

  return (
    <div className="flex flex-col gap-4">
      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (value.trim()) lookup.mutate();
        }}
      >
        <Input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="IP, domain, URL, SHA-256/MD5, or email — defanged (hxxp, [.]) is fine"
          className="min-w-72 flex-1 font-mono text-sm"
        />
        <div className="flex items-center gap-2">
          <Switch id="force" checked={force} onCheckedChange={setForce} />
          <Label htmlFor="force" className="text-xs">Bypass cache</Label>
        </div>
        <Button type="submit" disabled={lookup.isPending || !value.trim()}>
          {lookup.isPending ? <Loader2 className="animate-spin" /> : <Search />}
          Look up
        </Button>
      </form>

      {lookup.isError && (
        <p className="text-sm text-destructive">{lookup.error instanceof Error ? lookup.error.message : "Lookup failed"}</p>
      )}

      {result && (
        <div className="rounded-lg border p-4">
          <div className="flex flex-wrap items-center gap-2">
            <VerdictBadge verdict={result.verdict} />
            <span className="font-mono text-sm break-all">{result.value}</span>
            <span className="text-xs text-muted-foreground">{result.type}</span>
          </div>
          <div className="mt-3 grid gap-3 text-sm sm:grid-cols-3">
            <div>
              <p className="text-xs text-muted-foreground">Malicious score</p>
              <p className="tabular-nums">{result.maliciousScore != null ? result.maliciousScore.toFixed(2) : "—"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Sources</p>
              <p>{result.sources.length ? result.sources.join(", ") : "none"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Result</p>
              <p>{result.cached ? "Served from 24h cache" : "Fresh lookup"}</p>
            </div>
          </div>
          {result.geo && (
            <p className="mt-3 text-sm">
              <span className="text-xs text-muted-foreground">Location </span>
              {result.geo}
              {result.geoAttribution && <span className="ml-2 text-[11px] text-muted-foreground">{result.geoAttribution}</span>}
            </p>
          )}
          {result.reasons.length > 0 && (
            <ul className="mt-3 list-disc space-y-0.5 pl-5 text-sm">
              {result.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          )}
          {result.providersConfigured.length === 0 && (
            <p className="mt-3 text-xs text-muted-foreground">
              No external providers configured — an admin can add VirusTotal or AbuseIPDB keys under Settings. Built-in intel was applied.
            </p>
          )}
          {result.errors.map((e) => (
            <p key={e.provider} className="mt-2 text-xs text-destructive">{e.provider}: {e.error}</p>
          ))}
        </div>
      )}
    </div>
  );
}
