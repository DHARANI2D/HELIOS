"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Plus, Radio, Save, Trash2, Wand2 } from "lucide-react";
import { toast } from "sonner";

import { saveRulebookDraftAction, testApproverAction } from "@/app/(app)/rulebook/actions";
import {
  ACTION_MODES,
  AI_RESIDENCY,
  APPROVER_CHANNELS,
  MATCHER_KINDS,
  ON_TIMEOUT,
  OUT_OF_HOURS,
  RULED_ACTIONS,
  RULED_ACTION_LABEL,
  SEVERITIES,
  WINDOW_EFFECTS,
  type Approver,
  type Matcher,
  type PolicyWindow,
  type Rulebook,
} from "@/lib/rulebook/schema";
import { TEMPLATES, buildTemplate, type TemplateKey } from "@/lib/rulebook/templates";
import { diffRulebooks } from "@/lib/rulebook/diff";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";

export interface InventoryAsset {
  hostname: string;
  type: string | null;
  group: string;
  criticality: string;
}

interface Props {
  tenantId: string;
  initial: Rulebook;
  active: Rulebook | null;
  template: TemplateKey;
  timeZone: string;
  inventory: InventoryAsset[];
  accounts: string[];
  providers: Array<{ id: string; name: string; isLocal: boolean }>;
  canEdit: boolean;
}

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const ZONES = ["Asia/Kolkata", "UTC", "Asia/Dubai", "Asia/Singapore", "Europe/London", "Europe/Berlin", "America/New_York", "America/Los_Angeles", "Australia/Sydney"];

function Section({ step, title, hint, children }: { step: number; title: string; hint: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-3 rounded-lg border p-4">
      <div>
        <h3 className="flex items-center gap-2 text-sm font-semibold">
          <span className="flex size-5 items-center justify-center rounded-full bg-primary/10 text-[11px] text-primary">{step}</span>
          {title}
        </h3>
        <p className="mt-0.5 text-xs text-muted-foreground">{hint}</p>
      </div>
      {children}
    </section>
  );
}

function MatcherList({ items, onChange, disabled, label }: { items: Matcher[]; onChange: (m: Matcher[]) => void; disabled: boolean; label: string }) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label className="text-xs">{label}</Label>
      {items.length === 0 && <p className="text-[11px] text-muted-foreground">None yet.</p>}
      {items.map((m, i) => (
        <div key={i} className="flex flex-wrap gap-1.5">
          <NativeSelect className="h-8 w-36 text-xs" value={m.kind} disabled={disabled} onChange={(e) => onChange(items.map((x, j) => (j === i ? { ...x, kind: e.target.value as Matcher["kind"] } : x)))} aria-label="Match on">
            {Object.entries(MATCHER_KINDS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </NativeSelect>
          <Input className="h-8 min-w-32 flex-1 text-xs" value={m.value} disabled={disabled} placeholder={m.kind === "hostname" ? "DC-* or FIN-SQL-01" : m.kind === "criticality" ? "critical" : "value"} onChange={(e) => onChange(items.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))} aria-label="Value" />
          <Input className="h-8 min-w-32 flex-1 text-xs" value={m.note} disabled={disabled} placeholder="Why (shown in decisions)" onChange={(e) => onChange(items.map((x, j) => (j === i ? { ...x, note: e.target.value } : x)))} aria-label="Note" />
          {!disabled && <Button size="icon" variant="ghost" className="size-8" onClick={() => onChange(items.filter((_, j) => j !== i))} aria-label="Remove"><Trash2 /></Button>}
        </div>
      ))}
      {!disabled && (
        <Button size="sm" variant="outline" className="h-7 w-fit text-xs" onClick={() => onChange([...items, { kind: "hostname", value: "", note: "" }])}>
          <Plus /> Add rule
        </Button>
      )}
    </div>
  );
}

const toLocalInput = (iso: string) => {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
};

function WindowList({ items, onChange, disabled, label }: { items: PolicyWindow[]; onChange: (w: PolicyWindow[]) => void; disabled: boolean; label: string }) {
  const soon = () => {
    const start = new Date(Date.now() + 86_400_000);
    start.setMinutes(0, 0, 0);
    return { label: "", start: start.toISOString(), end: new Date(start.getTime() + 4 * 3_600_000).toISOString(), effect: "approve" as const };
  };
  return (
    <div className="flex flex-col gap-1.5">
      <Label className="text-xs">{label}</Label>
      {items.length === 0 && <p className="text-[11px] text-muted-foreground">None.</p>}
      {items.map((w, i) => {
        const set = (patch: Partial<PolicyWindow>) => onChange(items.map((x, j) => (j === i ? { ...x, ...patch } : x)));
        return (
          <div key={i} className="flex flex-wrap gap-1.5">
            <Input className="h-8 min-w-36 flex-1 text-xs" value={w.label} disabled={disabled} placeholder="Patch Tuesday, Diwali sale…" onChange={(e) => set({ label: e.target.value })} aria-label="Label" />
            <Input type="datetime-local" className="h-8 w-44 text-xs" value={toLocalInput(w.start)} disabled={disabled} onChange={(e) => e.target.value && set({ start: new Date(e.target.value).toISOString() })} aria-label="Starts" />
            <Input type="datetime-local" className="h-8 w-44 text-xs" value={toLocalInput(w.end)} disabled={disabled} onChange={(e) => e.target.value && set({ end: new Date(e.target.value).toISOString() })} aria-label="Ends" />
            <NativeSelect className="h-8 w-52 text-xs" value={w.effect} disabled={disabled} onChange={(e) => set({ effect: e.target.value as PolicyWindow["effect"] })} aria-label="Effect">
              {Object.entries(WINDOW_EFFECTS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </NativeSelect>
            {!disabled && <Button size="icon" variant="ghost" className="size-8" onClick={() => onChange(items.filter((_, j) => j !== i))} aria-label="Remove"><Trash2 /></Button>}
          </div>
        );
      })}
      {!disabled && <Button size="sm" variant="outline" className="h-7 w-fit text-xs" onClick={() => onChange([...items, soon()])}><Plus /> Add window</Button>}
    </div>
  );
}

const lines = (v: string) => v.split(/\r?\n|,/).map((x) => x.trim()).filter(Boolean);

export function RulebookEditor({ tenantId, initial, active, template, timeZone, inventory, accounts, providers, canEdit }: Props) {
  const router = useRouter();
  const [book, setBook] = React.useState<Rulebook>(initial);
  const [reason, setReason] = React.useState("");
  const [tpl, setTpl] = React.useState<TemplateKey>(template);
  const [filter, setFilter] = React.useState("");
  const disabled = !canEdit;
  const patch = <K extends keyof Rulebook>(key: K, value: Partial<Rulebook[K]>) => setBook((b) => ({ ...b, [key]: { ...(b[key] as object), ...value } }));

  const save = useMutation({
    mutationFn: () => saveRulebookDraftAction(tenantId, { body: book, reason, template: tpl }),
    onSuccess: (r) => {
      toast.success(`Draft v${r?.version} saved`);
      setReason("");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Couldn't save"),
  });
  const ping = useMutation({
    mutationFn: (a: Approver) => testApproverAction(tenantId, a),
    onSuccess: (r) => (r.ok ? toast.success(r.message) : toast.warning(r.message)),
    onError: (err) => toast.error(err instanceof Error ? err.message : "Test failed"),
  });

  const changes = React.useMemo(() => diffRulebooks(active, book), [active, book]);
  const hostRule = (list: Matcher[], host: string) => list.some((m) => m.kind === "hostname" && m.value.toLowerCase() === host.toLowerCase());
  const toggleHost = (key: "crownJewels" | "neverIsolate", host: string) => {
    const list = book.assets[key];
    patch("assets", { [key]: hostRule(list, host) ? list.filter((m) => !(m.kind === "hostname" && m.value.toLowerCase() === host.toLowerCase())) : [...list, { kind: "hostname", value: host, note: "" }] });
  };
  const shown = inventory.filter((a) => !filter || `${a.hostname} ${a.type ?? ""} ${a.group}`.toLowerCase().includes(filter.toLowerCase())).slice(0, 60);

  return (
    <div className="flex flex-col gap-4">
      <Section step={1} title="Start from an industry template" hint="Pre-fills sensible rules for the sector. Applying one replaces the form; nothing is saved until you save the draft.">
        <div className="flex flex-wrap items-center gap-2">
          <NativeSelect className="h-8 w-60 text-xs" value={tpl} disabled={disabled} onChange={(e) => setTpl(e.target.value as TemplateKey)} aria-label="Template">
            {Object.entries(TEMPLATES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </NativeSelect>
          {canEdit && (
            <Button size="sm" variant="outline" className="h-8" onClick={() => setBook(buildTemplate(tpl, book.schedule.timeZone || timeZone))}>
              <Wand2 /> Apply template
            </Button>
          )}
          <p className="w-full text-[11px] text-muted-foreground">{TEMPLATES[tpl].note}</p>
        </div>
      </Section>

      <Section step={2} title="Assets: crown jewels and never-isolate" hint="Tier-1 assets always go to a human. Never-isolate assets are never cut off by HELIOS, even when an analyst asks. Match by hostname (* wildcards), IP, asset group, type or criticality — or tick them from the inventory.">
        <div className="grid gap-4 lg:grid-cols-2">
          <MatcherList label="Crown jewels (tier 1)" items={book.assets.crownJewels} disabled={disabled} onChange={(m) => patch("assets", { crownJewels: m })} />
          <MatcherList label="Never isolate" items={book.assets.neverIsolate} disabled={disabled} onChange={(m) => patch("assets", { neverIsolate: m })} />
        </div>
        {inventory.length > 0 && (
          <details className="rounded-md border p-2">
            <summary className="cursor-pointer text-xs font-medium">Pick from this client&apos;s inventory ({inventory.length} assets)</summary>
            <Input className="mt-2 h-8 text-xs" placeholder="Filter by name, type or group" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter assets" />
            <div className="mt-2 max-h-64 overflow-auto">
              <table className="w-full text-xs">
                <thead className="text-left text-muted-foreground">
                  <tr><th className="py-1">Asset</th><th>Type</th><th>Criticality</th><th className="text-center">Tier 1</th><th className="text-center">Never isolate</th></tr>
                </thead>
                <tbody>
                  {shown.map((a) => (
                    <tr key={a.hostname} className="border-t">
                      <td className="py-1 font-mono">{a.hostname}</td>
                      <td>{a.type ?? a.group}</td>
                      <td>{a.criticality}</td>
                      <td className="text-center"><input type="checkbox" disabled={disabled} checked={hostRule(book.assets.crownJewels, a.hostname)} onChange={() => toggleHost("crownJewels", a.hostname)} aria-label={`${a.hostname} tier 1`} /></td>
                      <td className="text-center"><input type="checkbox" disabled={disabled} checked={hostRule(book.assets.neverIsolate, a.hostname)} onChange={() => toggleHost("neverIsolate", a.hostname)} aria-label={`${a.hostname} never isolate`} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
        )}
      </Section>

      <Section step={3} title="People: VIPs, break-glass and service accounts" hint="One account or pattern per line (jdoe, CORP\\svc-*, *@board.example). Break-glass and service accounts are never disabled through HELIOS; VIP accounts are disabled only with approval.">
        <div className="grid gap-3 md:grid-cols-3">
          {([
            ["vip", "VIP accounts"],
            ["breakGlass", "Break-glass accounts"],
            ["service", "Service accounts"],
          ] as const).map(([k, label]) => (
            <div key={k} className="grid gap-1.5">
              <Label htmlFor={`id-${k}`} className="text-xs">{label}</Label>
              <Textarea id={`id-${k}`} className="min-h-24 font-mono text-xs" disabled={disabled} defaultValue={book.identities[k].join("\n")} key={book.identities[k].join("|")} onBlur={(e) => patch("identities", { [k]: lines(e.target.value) })} />
            </div>
          ))}
        </div>
        {accounts.length > 0 && (
          <details className="rounded-md border p-2">
            <summary className="cursor-pointer text-xs font-medium">Accounts seen in this client&apos;s telemetry ({accounts.length})</summary>
            <div className="mt-2 flex flex-wrap gap-1">
              {accounts.slice(0, 120).map((u) => (
                <span key={u} className="inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[11px]">
                  {u}
                  {canEdit && (
                    <>
                      <button type="button" className="text-primary hover:underline" onClick={() => patch("identities", { vip: [...new Set([...book.identities.vip, u])] })}>VIP</button>
                      <button type="button" className="text-primary hover:underline" onClick={() => patch("identities", { service: [...new Set([...book.identities.service, u])] })}>service</button>
                    </>
                  )}
                </span>
              ))}
            </div>
          </details>
        )}
      </Section>

      <Section step={4} title="What HELIOS may do" hint="For each action: automatic (from a severity), needs approval, suggest only, or never. The plan and the client's AI consent still cap this; the rulebook can only restrict.">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="text-left text-muted-foreground">
              <tr><th className="py-1">Action</th><th>Mode</th><th>Automatic from</th><th className="text-center">Two people</th></tr>
            </thead>
            <tbody>
              {RULED_ACTIONS.map((a) => {
                const rule = book.actions[a];
                return (
                  <tr key={a} className="border-t">
                    <td className="py-1.5 pr-2 font-medium">{RULED_ACTION_LABEL[a]}</td>
                    <td className="pr-2">
                      <NativeSelect className="h-7 w-40 text-xs" value={rule.mode} disabled={disabled} onChange={(e) => patch("actions", { [a]: { ...rule, mode: e.target.value } } as Partial<Rulebook["actions"]>)} aria-label={`${RULED_ACTION_LABEL[a]} mode`}>
                        {Object.entries(ACTION_MODES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                      </NativeSelect>
                    </td>
                    <td className="pr-2">
                      <NativeSelect className="h-7 w-32 text-xs" value={rule.autoFrom} disabled={disabled || rule.mode !== "auto"} onChange={(e) => patch("actions", { [a]: { ...rule, autoFrom: e.target.value } } as Partial<Rulebook["actions"]>)} aria-label={`${RULED_ACTION_LABEL[a]} automatic from`}>
                        {SEVERITIES.map((s) => <option key={s} value={s}>{s.toLowerCase()}</option>)}
                      </NativeSelect>
                    </td>
                    <td className="text-center">
                      <input
                        type="checkbox"
                        disabled={disabled}
                        checked={book.blastRadius.twoPerson.includes(a)}
                        onChange={(e) => patch("blastRadius", { twoPerson: e.target.checked ? [...book.blastRadius.twoPerson, a] : book.blastRadius.twoPerson.filter((x) => x !== a) })}
                        aria-label={`${RULED_ACTION_LABEL[a]} needs two people`}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Section>

      <Section step={5} title="Blast radius and time boxes" hint="Above these limits automatic actions wait for a human, so a bad detection can't take out half the estate.">
        <div className="flex flex-wrap gap-4">
          <div className="grid gap-1.5">
            <Label htmlFor="br-hour" className="text-xs">Automatic actions per hour</Label>
            <Input id="br-hour" type="number" min={0} max={500} className="h-8 w-32" disabled={disabled} value={book.blastRadius.maxActionsPerHour} onChange={(e) => patch("blastRadius", { maxActionsPerHour: Math.max(0, Number(e.target.value) || 0) })} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="br-hosts" className="text-xs">Hosts isolated at once</Label>
            <Input id="br-hosts" type="number" min={0} max={10000} className="h-8 w-32" disabled={disabled} value={book.blastRadius.maxHostsIsolated} onChange={(e) => patch("blastRadius", { maxHostsIsolated: Math.max(0, Number(e.target.value) || 0) })} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="tb-ip" className="text-xs">IP blocks lift after (hours)</Label>
            <Input id="tb-ip" type="number" min={0} className="h-8 w-32" disabled={disabled} value={book.timeBoxes.blockIpHours} onChange={(e) => patch("timeBoxes", { blockIpHours: Math.max(0, Number(e.target.value) || 0) })} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="tb-user" className="text-xs">Disabled accounts re-enable after (hours)</Label>
            <Input id="tb-user" type="number" min={0} className="h-8 w-32" disabled={disabled} value={book.timeBoxes.disableUserHours} onChange={(e) => patch("timeBoxes", { disableUserHours: Math.max(0, Number(e.target.value) || 0) })} />
          </div>
        </div>
        <p className="text-[11px] text-muted-foreground">Time boxes undo an action on their own unless someone keeps it; 0 means it stays until a person lifts it.</p>
      </Section>

      <Section step={6} title="Hours, maintenance windows and change freezes" hint="In the client's own time zone. Outside business hours, during maintenance or a freeze, automatic actions can be held for approval or reduced to suggestions.">
        <div className="flex flex-wrap items-end gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="tz" className="text-xs">Time zone</Label>
            <Input id="tz" list="tz-list" className="h-8 w-48 text-xs" disabled={disabled} value={book.schedule.timeZone} onChange={(e) => patch("schedule", { timeZone: e.target.value })} />
            <datalist id="tz-list">{ZONES.map((z) => <option key={z} value={z} />)}</datalist>
          </div>
          <div className="grid gap-1.5">
            <Label className="text-xs">Business days</Label>
            <div className="flex gap-1">
              {DAYS.map((d, i) => (
                <button
                  key={d}
                  type="button"
                  disabled={disabled}
                  onClick={() => patch("schedule", { businessDays: book.schedule.businessDays.includes(i) ? book.schedule.businessDays.filter((x) => x !== i) : [...book.schedule.businessDays, i].sort() })}
                  className={cn("h-8 w-10 rounded border text-xs", book.schedule.businessDays.includes(i) ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground")}
                  aria-pressed={book.schedule.businessDays.includes(i)}
                >
                  {d}
                </button>
              ))}
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="bh-start" className="text-xs">From</Label>
            <Input id="bh-start" type="time" className="h-8 w-28" disabled={disabled} value={book.schedule.businessStart} onChange={(e) => patch("schedule", { businessStart: e.target.value })} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="bh-end" className="text-xs">To</Label>
            <Input id="bh-end" type="time" className="h-8 w-28" disabled={disabled} value={book.schedule.businessEnd} onChange={(e) => patch("schedule", { businessEnd: e.target.value })} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="ooh" className="text-xs">Outside business hours</Label>
            <NativeSelect id="ooh" className="h-8 w-60 text-xs" disabled={disabled} value={book.schedule.outOfHours} onChange={(e) => patch("schedule", { outOfHours: e.target.value as Rulebook["schedule"]["outOfHours"] })}>
              {Object.entries(OUT_OF_HOURS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </NativeSelect>
          </div>
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          <WindowList label="Maintenance windows" items={book.schedule.maintenance} disabled={disabled} onChange={(w) => patch("schedule", { maintenance: w })} />
          <WindowList label="Change freezes" items={book.schedule.freezes} disabled={disabled} onChange={(w) => patch("schedule", { freezes: w })} />
        </div>
      </Section>

      <Section step={7} title="Approvers and escalation" hint="Who is asked, in order, and how long each has before the next is asked. HELIOS notifies app users and posts to the client's Slack or Teams; for email and phone it asks the SOC to make contact. Test each one.">
        {book.approvers.chain.map((a, i) => {
          const set = (p: Partial<Approver>) => patch("approvers", { chain: book.approvers.chain.map((x, j) => (j === i ? { ...x, ...p } : x)) });
          return (
            <div key={i} className="flex flex-wrap items-center gap-1.5">
              <span className="w-5 text-xs text-muted-foreground">{i + 1}.</span>
              <Input className="h-8 w-40 text-xs" value={a.name} disabled={disabled} placeholder="Name" onChange={(e) => set({ name: e.target.value })} aria-label="Approver name" />
              <NativeSelect className="h-8 w-36 text-xs" value={a.channel} disabled={disabled} onChange={(e) => set({ channel: e.target.value as Approver["channel"] })} aria-label="Channel">
                {Object.entries(APPROVER_CHANNELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </NativeSelect>
              <Input className="h-8 min-w-40 flex-1 text-xs" value={a.contact} disabled={disabled} placeholder={a.channel === "phone" ? "+91 …" : "name@client.example"} onChange={(e) => set({ contact: e.target.value })} aria-label="Contact" />
              <Input type="number" min={1} max={1440} className="h-8 w-20 text-xs" value={a.timeoutMinutes} disabled={disabled} onChange={(e) => set({ timeoutMinutes: Math.max(1, Number(e.target.value) || 15) })} aria-label="Minutes before escalating" />
              <span className="text-[11px] text-muted-foreground">min</span>
              {canEdit && (
                <>
                  <Button size="sm" variant="outline" className="h-8 text-xs" onClick={() => ping.mutate(a)} disabled={ping.isPending || !a.name || !a.contact}><Radio /> Test</Button>
                  <Button size="icon" variant="ghost" className="size-8" onClick={() => patch("approvers", { chain: book.approvers.chain.filter((_, j) => j !== i) })} aria-label="Remove approver"><Trash2 /></Button>
                </>
              )}
            </div>
          );
        })}
        {canEdit && book.approvers.chain.length < 10 && (
          <Button size="sm" variant="outline" className="h-7 w-fit text-xs" onClick={() => patch("approvers", { chain: [...book.approvers.chain, { name: "", contact: "", channel: "app", timeoutMinutes: 15 }] })}>
            <Plus /> Add approver
          </Button>
        )}
        <div className="flex items-center gap-2">
          <Label htmlFor="on-timeout" className="text-xs">When nobody answers</Label>
          <NativeSelect id="on-timeout" className="h-8 w-60 text-xs" disabled={disabled} value={book.approvers.onTimeout} onChange={(e) => patch("approvers", { onTimeout: e.target.value as Rulebook["approvers"]["onTimeout"] })}>
            {Object.entries(ON_TIMEOUT).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </NativeSelect>
        </div>
      </Section>

      <Section step={8} title="Data handling and AI" hint="Where AI inference on this client's evidence may run, which providers are allowed, and whether personal data is masked before it reaches a cloud model.">
        <div className="flex flex-wrap items-end gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="residency" className="text-xs">AI residency</Label>
            <NativeSelect id="residency" className="h-8 w-64 text-xs" disabled={disabled} value={book.dataHandling.residency} onChange={(e) => patch("dataHandling", { residency: e.target.value as Rulebook["dataHandling"]["residency"] })}>
              {Object.entries(AI_RESIDENCY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </NativeSelect>
          </div>
          {book.dataHandling.residency === "region" && (
            <div className="grid gap-1.5">
              <Label htmlFor="regions" className="text-xs">Allowed regions</Label>
              <Input id="regions" className="h-8 w-56 text-xs" disabled={disabled} placeholder="india, eu" defaultValue={book.dataHandling.regions.join(", ")} onBlur={(e) => patch("dataHandling", { regions: lines(e.target.value).map((r) => r.toLowerCase()) })} />
            </div>
          )}
          <label className="flex items-center gap-2 text-xs"><Switch checked={book.dataHandling.redactPii} disabled={disabled} onCheckedChange={(v) => patch("dataHandling", { redactPii: v })} /> Mask personal data for cloud models</label>
          <label className="flex items-center gap-2 text-xs"><Switch checked={book.dataHandling.allowUserChoice} disabled={disabled} onCheckedChange={(v) => patch("dataHandling", { allowUserChoice: v })} /> Users may pick their own model</label>
        </div>
        {providers.length > 0 && (
          <div className="grid gap-1.5">
            <Label className="text-xs">Allowed AI providers <span className="font-normal text-muted-foreground">(none ticked = any provider HELIOS offers)</span></Label>
            <div className="flex flex-wrap gap-3">
              {providers.map((p) => (
                <label key={p.id} className="flex items-center gap-1.5 text-xs">
                  <input
                    type="checkbox"
                    disabled={disabled}
                    checked={book.dataHandling.allowedProviders.includes(p.id)}
                    onChange={(e) => patch("dataHandling", { allowedProviders: e.target.checked ? [...book.dataHandling.allowedProviders, p.id] : book.dataHandling.allowedProviders.filter((x) => x !== p.id) })}
                  />
                  {p.name} {p.isLocal && <Badge variant="outline" className="text-[10px]">local</Badge>}
                </label>
              ))}
            </div>
          </div>
        )}
      </Section>

      <Section step={9} title="Obligations and review" hint="Regulated entities in India report qualifying incidents to CERT-In within 6 hours; record who reports for this client. The rulebook comes up for review on this schedule.">
        <label className="flex items-center gap-2 text-xs"><Switch checked={book.obligations.regulatedEntity} disabled={disabled} onCheckedChange={(v) => patch("obligations", { regulatedEntity: v })} /> Regulated entity (CERT-In reporting applies)</label>
        <div className="grid gap-2 sm:grid-cols-3">
          {(["name", "email", "phone"] as const).map((k) => (
            <div key={k} className="grid gap-1.5">
              <Label htmlFor={`certin-${k}`} className="text-xs">CERT-In point of contact · {k}</Label>
              <Input id={`certin-${k}`} className="h-8 text-xs" disabled={disabled} value={book.obligations.certInContact[k]} onChange={(e) => patch("obligations", { certInContact: { ...book.obligations.certInContact, [k]: e.target.value } })} />
            </div>
          ))}
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <div className="grid min-w-72 flex-1 gap-1.5">
            <Label htmlFor="recipients" className="text-xs">Incident report recipients (emails)</Label>
            <Input id="recipients" className="h-8 text-xs" disabled={disabled} defaultValue={book.obligations.reportRecipients.join(", ")} onBlur={(e) => patch("obligations", { reportRecipients: lines(e.target.value) })} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="review" className="text-xs">Review every (days)</Label>
            <Input id="review" type="number" min={7} max={365} className="h-8 w-28" disabled={disabled} value={book.reviewEveryDays} onChange={(e) => setBook({ ...book, reviewEveryDays: Math.min(365, Math.max(7, Number(e.target.value) || 90)) })} />
          </div>
        </div>
      </Section>

      {canEdit && (
        <div className="sticky bottom-0 flex flex-col gap-2 rounded-lg border bg-background/95 p-3 backdrop-blur">
          <details>
            <summary className="cursor-pointer text-xs text-muted-foreground">{changes.length} change{changes.length === 1 ? "" : "s"} from {active ? "the version in force" : "an empty rulebook"}</summary>
            <ul className="mt-1 max-h-40 overflow-auto font-mono text-[11px]">
              {changes.map((c, i) => (
                <li key={i} className={c.kind === "removed" ? "text-destructive" : c.kind === "added" ? "text-success" : ""}>
                  {c.kind === "changed" ? `~ ${c.path}: ${c.before} → ${c.after}` : `${c.kind === "added" ? "+" : "−"} ${c.path}: ${c.after ?? c.before}`}
                </li>
              ))}
            </ul>
          </details>
          <div className="flex flex-wrap gap-2">
            <Input className="h-8 min-w-64 flex-1 text-xs" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why these rules (required, kept with the version)" aria-label="Reason for this version" />
            <Button size="sm" onClick={() => save.mutate()} disabled={save.isPending || reason.trim().length < 3}>
              {save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save draft
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
