"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Plus, Save, Trash2, Wrench } from "lucide-react";
import { toast } from "sonner";

import {
  addCatalogToolAction,
  deleteCurrencyAction,
  deleteModelPriceAction,
  deleteVolumeTierAction,
  saveCurrencyAction,
  saveModelPriceAction,
  saveToolPriceAction,
  saveVolumeTierAction,
  type CustomToolInput,
} from "@/app/(app)/pricing/actions";
import { CATEGORIES, UNIT_LABEL, toolLabel, type PriceUnit, type ToolDefinition } from "@/lib/integrations/catalog";
import { CONTROLS } from "@/lib/endpoints/controls";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { parseAmount } from "@/components/pricing/price-book";

function useAction<A extends unknown[]>(fn: (...args: A) => Promise<unknown>, ok: string) {
  const router = useRouter();
  return useMutation({
    mutationFn: (args: A) => fn(...args),
    onSuccess: () => {
      toast.success(ok);
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
}

// --- tool catalog

function ToolRow({ tool, canEdit }: { tool: ToolDefinition; canEdit: boolean }) {
  const [price, setPrice] = React.useState(tool.price.custom == null ? "" : String(tool.price.custom));
  const parsed = parseAmount(price);
  const save = useAction(saveToolPriceAction, `${tool.name} saved`);
  const dirty = parsed !== tool.price.custom;
  return (
    <tr className={tool.active ? "" : "opacity-60"}>
      <td className="py-2 pr-3">
        <p className="text-sm font-medium">{toolLabel(tool)}</p>
        <p className="text-[11px] text-muted-foreground">{CATEGORIES.find((c) => c.key === tool.category)?.label} · {UNIT_LABEL[tool.price.unit]}</p>
      </td>
      <td className="px-2 py-2 text-xs">
        {tool.price.list == null ? <span className="text-muted-foreground">Not published</span> : <span className="tabular">${tool.price.list.toFixed(2)}</span>}
        {tool.price.source && <p className="max-w-64 truncate text-[11px] text-muted-foreground" title={tool.price.source}>{tool.price.source}</p>}
      </td>
      <td className="px-2 py-2">
        <div className="flex items-center gap-1">
          <Input value={price} onChange={(e) => setPrice(e.target.value)} disabled={!canEdit} className="h-8 w-24 text-right tabular" inputMode="decimal" aria-label={`Your price for ${tool.name}`} />
          {tool.price.list == null && tool.price.custom == null && <Badge variant="warning">needed to quote</Badge>}
        </div>
      </td>
      <td className="px-2 py-2">
        <Switch checked={tool.active} disabled={!canEdit || save.isPending} onCheckedChange={(v) => parsed !== "invalid" && save.mutate([tool.key, parsed, v])} aria-label={`${tool.name} offered`} />
      </td>
      <td className="py-2 text-right">
        {canEdit && dirty && (
          <Button size="sm" className="h-7" disabled={save.isPending || parsed === "invalid"} onClick={() => parsed !== "invalid" && save.mutate([tool.key, parsed, tool.active])}>
            {save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save
          </Button>
        )}
      </td>
    </tr>
  );
}

const EMPTY_TOOL: CustomToolInput = { key: "", name: "", vendor: "", category: "edr", description: "", controls: [], actions: [], ingest: "generic", platforms: [], deployment: "cloud", offlineCapable: false, priceUnit: "endpoint", customPrice: null };

function AddToolDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const [d, setD] = React.useState<CustomToolInput>(EMPTY_TOOL);
  const [platforms, setPlatforms] = React.useState("");
  const [price, setPrice] = React.useState("");
  const add = useAction(addCatalogToolAction, "Tool added to the catalog");
  const submit = () => {
    const p = parseAmount(price);
    if (p === "invalid") return toast.error("Price: enter a number or leave it empty");
    add.mutate([{ ...d, key: d.key || `${d.vendor}_${d.name}`.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, ""), platforms: platforms.split(",").map((x) => x.trim()).filter(Boolean), customPrice: p }], { onSuccess: () => onOpenChange(false) });
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><Wrench className="size-4" /> Add a tool</DialogTitle>
          <DialogDescription>For a product that isn&apos;t in the catalog — a regional vendor, or a service you deliver yourselves.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="grid gap-1.5"><Label className="text-xs">Vendor</Label><Input value={d.vendor} onChange={(e) => setD({ ...d, vendor: e.target.value })} /></div>
          <div className="grid gap-1.5"><Label className="text-xs">Product</Label><Input value={d.name} onChange={(e) => setD({ ...d, name: e.target.value })} /></div>
          <div className="grid gap-1.5">
            <Label className="text-xs">Category</Label>
            <NativeSelect value={d.category} onChange={(e) => setD({ ...d, category: e.target.value })}>
              {CATEGORIES.map((c) => <option key={c.key} value={c.key}>{c.label}</option>)}
            </NativeSelect>
          </div>
          <div className="grid gap-1.5">
            <Label className="text-xs">Deployment</Label>
            <NativeSelect value={d.deployment} onChange={(e) => setD({ ...d, deployment: e.target.value as CustomToolInput["deployment"] })}>
              <option value="cloud">Cloud</option>
              <option value="self-hosted">Self-hosted</option>
              <option value="hybrid">Hybrid</option>
            </NativeSelect>
          </div>
          <div className="grid gap-1.5 sm:col-span-2"><Label className="text-xs">What it does</Label><Textarea rows={2} value={d.description} onChange={(e) => setD({ ...d, description: e.target.value })} /></div>
          <div className="grid gap-1.5">
            <Label className="text-xs">Priced per</Label>
            <NativeSelect value={d.priceUnit} onChange={(e) => setD({ ...d, priceUnit: e.target.value as PriceUnit })}>
              {(Object.keys(UNIT_LABEL) as PriceUnit[]).map((u) => <option key={u} value={u}>{UNIT_LABEL[u]}</option>)}
            </NativeSelect>
          </div>
          <div className="grid gap-1.5"><Label className="text-xs">Your price (USD)</Label><Input value={price} onChange={(e) => setPrice(e.target.value)} inputMode="decimal" className="tabular" /></div>
          <div className="grid gap-1.5">
            <Label className="text-xs">Alert format</Label>
            <NativeSelect value={d.ingest ?? "none"} onChange={(e) => setD({ ...d, ingest: e.target.value === "none" ? null : (e.target.value as CustomToolInput["ingest"]) })}>
              <option value="none">Doesn&apos;t send alerts</option>
              <option value="generic">Generic JSON</option>
              <option value="crowdstrike">CrowdStrike-style</option>
              <option value="defender">Microsoft Graph security alerts</option>
              <option value="sentinelone">SentinelOne-style</option>
              <option value="wazuh">Wazuh alerts</option>
              <option value="entra">Entra ID risk / sign-ins</option>
              <option value="okta">Okta System Log</option>
            </NativeSelect>
          </div>
          <div className="grid gap-1.5"><Label className="text-xs">Platforms (comma-separated)</Label><Input value={platforms} onChange={(e) => setPlatforms(e.target.value)} /></div>
          <div className="grid gap-1.5 sm:col-span-2">
            <Label className="text-xs">Protection it provides</Label>
            <div className="flex flex-wrap gap-1.5">
              {CONTROLS.map((c) => {
                const on = d.controls.includes(c.key);
                return (
                  <button key={c.key} type="button" onClick={() => setD({ ...d, controls: on ? d.controls.filter((x) => x !== c.key) : [...d.controls, c.key] })} className={`rounded-full border px-2.5 py-0.5 text-xs ${on ? "border-primary bg-primary text-primary-foreground" : "hover:bg-accent"}`} aria-pressed={on}>
                    {c.short}
                  </button>
                );
              })}
            </div>
          </div>
          <label className="flex items-center gap-2 text-sm sm:col-span-2"><Switch checked={d.offlineCapable} onCheckedChange={(v) => setD({ ...d, offlineCapable: v })} /> Works without internet access</label>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={submit} disabled={add.isPending || !d.name.trim() || !d.vendor.trim() || d.description.trim().length < 3}>
            {add.isPending && <Loader2 className="animate-spin" />} Add tool
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function ToolCatalogEditor({ tools, canEdit }: { tools: ToolDefinition[]; canEdit: boolean }) {
  const priced = CATEGORIES.filter((c) => c.priced);
  const [category, setCategory] = React.useState<string>(priced[0].key);
  const [adding, setAdding] = React.useState(false);
  const needs = tools.filter((t) => t.active && priced.some((c) => c.key === t.category) && t.price.list == null && t.price.custom == null).length;
  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-muted-foreground">
        List prices are the vendor&apos;s own published prices, with their source. Quote-only vendors have none — enter what you pay or resell at before quoting them.
        {needs > 0 && ` ${needs} offered tool${needs === 1 ? " needs" : "s need"} your price.`}
      </p>
      <div className="flex flex-wrap gap-1.5">
        {priced.map((c) => (
          <button key={c.key} type="button" onClick={() => setCategory(c.key)} className={`rounded-full border px-3 py-1 text-xs font-medium hover:bg-accent ${category === c.key ? "border-primary bg-primary text-primary-foreground hover:bg-primary/90" : ""}`}>
            {c.label} <span className="opacity-70">· {tools.filter((t) => t.category === c.key).length}</span>
          </button>
        ))}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[40rem]">
          <thead>
            <tr className="border-b text-left text-xs text-muted-foreground">
              <th className="py-2 pr-3 font-medium">Tool</th>
              <th className="px-2 py-2 font-medium">Vendor list price</th>
              <th className="px-2 py-2 font-medium">Your price</th>
              <th className="px-2 py-2 font-medium">Offered</th>
              <th />
            </tr>
          </thead>
          <tbody className="divide-y">
            {tools.filter((t) => t.category === category).map((t) => <ToolRow key={t.key} tool={t} canEdit={canEdit} />)}
            {tools.filter((t) => t.category === category).length === 0 && (
              <tr><td colSpan={5} className="py-6 text-center text-xs text-muted-foreground">No tools in this category yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      {canEdit && (
        <Button size="sm" variant="outline" className="self-start" onClick={() => setAdding(true)}><Plus /> Add a tool</Button>
      )}
      {adding && <AddToolDialog open onOpenChange={setAdding} />}
    </div>
  );
}

// --- volume discounts

export function VolumeEditor({ tiers, canEdit }: { tiers: Array<{ minEndpoints: number; discountPct: number }>; canEdit: boolean }) {
  const [min, setMin] = React.useState("");
  const [pct, setPct] = React.useState("");
  const save = useAction(saveVolumeTierAction, "Tier saved");
  const remove = useAction(deleteVolumeTierAction, "Tier removed");
  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-muted-foreground">Discount on the plan&apos;s per-endpoint fee once a client reaches a size. No tiers means no volume discount.</p>
      {tiers.length > 0 && (
        <table className="w-full max-w-md text-sm">
          <thead><tr className="border-b text-left text-xs text-muted-foreground"><th className="py-2 font-medium">From endpoints</th><th className="py-2 font-medium">Discount</th><th /></tr></thead>
          <tbody className="divide-y">
            {tiers.map((t) => (
              <tr key={t.minEndpoints}>
                <td className="py-1.5 tabular">{t.minEndpoints.toLocaleString("en-US")}</td>
                <td className="py-1.5 tabular">{t.discountPct}%</td>
                <td className="py-1.5 text-right">{canEdit && <Button size="icon" variant="ghost" className="size-7" aria-label="Remove tier" onClick={() => remove.mutate([t.minEndpoints])}><Trash2 /></Button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {canEdit && (
        <div className="flex flex-wrap items-end gap-2">
          <div className="grid gap-1.5"><Label className="text-xs">From endpoints</Label><Input value={min} onChange={(e) => setMin(e.target.value)} inputMode="numeric" className="h-8 w-32 tabular" /></div>
          <div className="grid gap-1.5"><Label className="text-xs">Discount %</Label><Input value={pct} onChange={(e) => setPct(e.target.value)} inputMode="decimal" className="h-8 w-24 tabular" /></div>
          <Button size="sm" className="h-8" disabled={save.isPending || !min || !pct} onClick={() => save.mutate([Number(min), Number(pct)], { onSuccess: () => { setMin(""); setPct(""); } })}><Plus /> Add tier</Button>
        </div>
      )}
    </div>
  );
}

// --- currencies

export function CurrencyEditor({ currencies, canEdit }: { currencies: Array<{ code: string; symbol: string; rate: number; updatedAt: string }>; canEdit: boolean }) {
  const [code, setCode] = React.useState("");
  const [symbol, setSymbol] = React.useState("");
  const [rate, setRate] = React.useState("");
  const save = useAction(saveCurrencyAction, "Currency saved");
  const remove = useAction(deleteCurrencyAction, "Currency removed");
  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-muted-foreground">Prices are kept in USD. Add each currency you quote in with the rate you bill at (units per 1 USD), and keep it current.</p>
      <table className="w-full max-w-lg text-sm">
        <thead><tr className="border-b text-left text-xs text-muted-foreground"><th className="py-2 font-medium">Code</th><th className="py-2 font-medium">Symbol</th><th className="py-2 font-medium">Rate (per USD)</th><th className="py-2 font-medium">Updated</th><th /></tr></thead>
        <tbody className="divide-y">
          {currencies.map((c) => (
            <tr key={c.code}>
              <td className="py-1.5 font-mono">{c.code}</td>
              <td className="py-1.5">{c.symbol}</td>
              <td className="py-1.5 tabular">{c.code === "USD" ? "1 (base)" : c.rate}</td>
              <td className="py-1.5 text-xs text-muted-foreground">{c.updatedAt.slice(0, 10)}</td>
              <td className="py-1.5 text-right">{canEdit && c.code !== "USD" && <Button size="icon" variant="ghost" className="size-7" aria-label={`Remove ${c.code}`} onClick={() => remove.mutate([c.code])}><Trash2 /></Button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {canEdit && (
        <div className="flex flex-wrap items-end gap-2">
          <div className="grid gap-1.5"><Label className="text-xs">ISO code</Label><Input value={code} onChange={(e) => setCode(e.target.value.toUpperCase())} maxLength={3} className="h-8 w-20 font-mono" /></div>
          <div className="grid gap-1.5"><Label className="text-xs">Symbol</Label><Input value={symbol} onChange={(e) => setSymbol(e.target.value)} maxLength={6} className="h-8 w-20" /></div>
          <div className="grid gap-1.5"><Label className="text-xs">Units per 1 USD</Label><Input value={rate} onChange={(e) => setRate(e.target.value)} inputMode="decimal" className="h-8 w-32 tabular" /></div>
          <Button size="sm" className="h-8" disabled={save.isPending || code.length !== 3 || !symbol || !rate} onClick={() => save.mutate([code, symbol, Number(rate)], { onSuccess: () => { setCode(""); setSymbol(""); setRate(""); } })}><Save /> Save currency</Button>
        </div>
      )}
    </div>
  );
}

// --- AI model prices

export function ModelPriceEditor({ models, canEdit }: { models: Array<{ model: string; provider: string; inputPer: number; outputPer: number; source: string | null }>; canEdit: boolean }) {
  const [d, setD] = React.useState({ model: "", provider: "", inputPer: "", outputPer: "", source: "" });
  const save = useAction(saveModelPriceAction, "Model price saved");
  const remove = useAction(deleteModelPriceAction, "Model price removed");
  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-muted-foreground">USD per million tokens, used for AI spend on the AI page and cloud AI estimates in quotes. Local models cost nothing per token; add them at 0 to list them.</p>
      <table className="w-full max-w-2xl text-sm">
        <thead><tr className="border-b text-left text-xs text-muted-foreground"><th className="py-2 font-medium">Model</th><th className="py-2 font-medium">Provider</th><th className="py-2 text-right font-medium">Input</th><th className="py-2 text-right font-medium">Output</th><th className="py-2 pl-3 font-medium">Source</th><th /></tr></thead>
        <tbody className="divide-y">
          {models.map((m) => (
            <tr key={m.model}>
              <td className="py-1.5 font-mono text-xs">{m.model}</td>
              <td className="py-1.5 text-xs">{m.provider}</td>
              <td className="py-1.5 text-right tabular">${m.inputPer}</td>
              <td className="py-1.5 text-right tabular">${m.outputPer}</td>
              <td className="py-1.5 pl-3 text-xs text-muted-foreground">{m.source ?? "—"}</td>
              <td className="py-1.5 text-right">{canEdit && <Button size="icon" variant="ghost" className="size-7" aria-label={`Remove ${m.model}`} onClick={() => remove.mutate([m.model])}><Trash2 /></Button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {canEdit && (
        <div className="flex flex-wrap items-end gap-2">
          <div className="grid gap-1.5"><Label className="text-xs">Model ID</Label><Input value={d.model} onChange={(e) => setD({ ...d, model: e.target.value })} className="h-8 w-52 font-mono text-xs" /></div>
          <div className="grid gap-1.5"><Label className="text-xs">Provider</Label><Input value={d.provider} onChange={(e) => setD({ ...d, provider: e.target.value })} className="h-8 w-32" /></div>
          <div className="grid gap-1.5"><Label className="text-xs">Input $/M</Label><Input value={d.inputPer} onChange={(e) => setD({ ...d, inputPer: e.target.value })} inputMode="decimal" className="h-8 w-20 tabular" /></div>
          <div className="grid gap-1.5"><Label className="text-xs">Output $/M</Label><Input value={d.outputPer} onChange={(e) => setD({ ...d, outputPer: e.target.value })} inputMode="decimal" className="h-8 w-20 tabular" /></div>
          <div className="grid gap-1.5"><Label className="text-xs">Source</Label><Input value={d.source} onChange={(e) => setD({ ...d, source: e.target.value })} className="h-8 w-40" /></div>
          <Button size="sm" className="h-8" disabled={save.isPending || !d.model || !d.provider || d.inputPer === "" || d.outputPer === ""} onClick={() => save.mutate([{ model: d.model, provider: d.provider, inputPer: Number(d.inputPer), outputPer: Number(d.outputPer), source: d.source || null }], { onSuccess: () => setD({ model: "", provider: "", inputPer: "", outputPer: "", source: "" }) })}><Save /> Save</Button>
        </div>
      )}
    </div>
  );
}
