"use client";

import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Bookmark, ChevronDown, ChevronRight, Download, HelpCircle, Loader2, Minus, Plus, Search, Sparkles, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { deleteSearchAction, eventDetailAction, moreEventsAction, saveSearchAction, suggestSearchAction } from "@/app/(app)/explore/actions";
import { FIELDS, RANGES, filterFor, type RangeKey } from "@/lib/explore/query";
import { unwrap } from "@/lib/action-result";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { JsonView } from "@/components/shared/json-view";
import { Histogram } from "@/components/explore/histogram";

interface Row {
  id: string;
  timestamp: string;
  source: string;
  platform: string | null;
  eventType: string;
  userName: string | null;
  hostName: string | null;
  processName: string | null;
  commandLine: string | null;
  sourceIp: string | null;
  destIp: string | null;
  destPort: number | null;
  filePath: string | null;
  fileHash: string | null;
  severityHint: string | null;
  tenantId: string | null;
  caseId: string | null;
  integrationId: string | null;
}

interface Result {
  rows: Row[];
  next: string | null;
  total: number;
  from: string;
  to: string;
  bucketSeconds: number;
  histogram: Array<{ t: string; n: number }>;
  facets: Array<{ key: string; label: string; values: Array<{ value: string; label: string; n: number }> }>;
  ms: number;
}

interface Saved {
  id: string;
  name: string;
  query: string;
  range: string;
  tenant: string | null;
  tenantName: string | null;
  shared: boolean;
  mine: boolean;
  owner: string;
}

interface Props {
  params: { q: string; range: RangeKey | "custom"; from: string; to: string; tenant: string };
  isClient: boolean;
  error: string | null;
  result: Result | null;
  tenants: Array<{ id: string; name: string; isTest: boolean }>;
  saved: Saved[];
  assistant: string | null;
}

const EXAMPLES = ["Failed sign-ins in the last 24 hours", "PowerShell with encoded commands this week", "Connections to 203.0.113.7", "What did administrator do on FIN-WS-04 today"];

function hrefFor(p: { q: string; range: string; from?: string; to?: string; tenant: string }) {
  const s = new URLSearchParams();
  if (p.q) s.set("q", p.q);
  if (p.range === "custom" && p.from) {
    s.set("from", p.from);
    if (p.to) s.set("to", p.to);
  } else s.set("range", p.range);
  s.set("tenant", p.tenant);
  return `/explore?${s.toString()}`;
}

const fmt = (iso: string) => iso.replace("T", " ").slice(0, 19);

function summary(r: Row) {
  if (r.commandLine) return r.commandLine;
  const dst = r.destIp ? `${r.destIp}${r.destPort != null ? `:${r.destPort}` : ""}` : r.destPort != null ? `port ${r.destPort}` : null;
  const net = r.sourceIp && dst ? `${r.sourceIp} → ${dst}` : r.sourceIp ? `from ${r.sourceIp}` : dst ? `to ${dst}` : "";
  return [r.processName, net, r.filePath].filter(Boolean).join(" · ") || "—";
}

export function ExploreView({ params, isClient, error, result, tenants, saved, assistant }: Props) {
  const router = useRouter();
  const [q, setQ] = React.useState(params.q);
  const [range, setRange] = React.useState<string>(params.range);
  const [tenant, setTenant] = React.useState(params.tenant);
  const [question, setQuestion] = React.useState("");
  const [open, setOpen] = React.useState<string | null>(null);
  const [help, setHelp] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [explained, setExplained] = React.useState<{ query: string; text: string; engine: string; note?: string } | null>(null);
  const [rows, setRows] = React.useState<Row[]>(result?.rows ?? []);
  const [next, setNext] = React.useState<string | null>(result?.next ?? null);
  // A new search (the URL changed): take its results and parameters, keep
  // what the assistant said about it.
  const [shown, setShown] = React.useState({ result, params });
  if (shown.result !== result || shown.params !== params) {
    setShown({ result, params });
    setRows(result?.rows ?? []);
    setNext(result?.next ?? null);
    setOpen(null);
    setQ(params.q);
    setRange(params.range);
    setTenant(params.tenant);
  }
  const tenantName = new Map(tenants.map((t) => [t.id, t.name]));
  const showClient = !isClient && params.tenant === "all";

  const run = (over: Partial<{ q: string; range: string; from: string; to: string; tenant: string }> = {}) =>
    router.push(hrefFor({ q, range: range === "custom" ? "24h" : range, tenant, ...over }));
  const addFilter = (field: string, value: string, negate = false) => {
    const f = filterFor(field, value, negate);
    const nextQ = q.trim() ? `${q.trim()} ${f}` : f;
    setQ(nextQ);
    router.push(hrefFor({ q: nextQ, range: params.range, from: params.from, to: params.to, tenant }));
  };

  const ask = useMutation({
    mutationFn: () => unwrap(suggestSearchAction(question, tenant)),
    onSuccess: (s) => {
      setQ(s.query);
      setExplained({ query: s.query, text: s.explanation, engine: s.model ? `${s.engine} (${s.model})` : s.engine, note: s.note });
      const r = s.range ?? (range === "custom" ? "24h" : range);
      setRange(r);
      router.push(hrefFor({ q: s.query, range: r, tenant }));
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const more = useMutation({
    mutationFn: () => unwrap(moreEventsAction({ q: params.q, ...(params.range === "custom" ? { from: params.from, to: params.to } : { range: params.range }), tenant: params.tenant }, next!)),
    onSuccess: (r) => {
      setRows((prev) => [...prev, ...r.rows]);
      setNext(r.next);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const exportHref = `/explore/export?${new URLSearchParams({ q: params.q, ...(params.range === "custom" ? { from: params.from, to: params.to } : { range: params.range }), tenant: params.tenant }).toString()}`;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <p className="flex items-center gap-2 text-sm text-muted-foreground"><Search className="size-4" /> {isClient ? "Your logs, from all your security tools" : "Every client's logs, from all their tools"}</p>
        <h2 className="text-xl font-semibold tracking-tight">{isClient ? "Search logs" : "Explore"}</h2>
      </div>

      <Card>
        <CardContent className="flex flex-col gap-3">
          <form
            className="flex flex-wrap gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (question.trim()) ask.mutate();
            }}
          >
            <div className="relative min-w-64 flex-1">
              <Sparkles className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-chart-4" />
              <Input value={question} onChange={(e) => setQuestion(e.target.value)} placeholder={`Ask in plain words, e.g. "${EXAMPLES[0]}"`} className="pl-8" maxLength={600} aria-label="Ask the search assistant" />
            </div>
            <Button type="submit" variant="outline" disabled={ask.isPending || !question.trim()}>
              {ask.isPending ? <Loader2 className="animate-spin" /> : <Sparkles />} Write the search
            </Button>
          </form>
          <p className="-mt-1 text-xs text-muted-foreground">
            The search assistant runs on {assistant ?? "the built-in translator (no model set up)"}. It writes the search below; it never reads the logs.
          </p>
          {explained && explained.query === params.q && (
            <div className="rounded-md border border-chart-4/30 bg-chart-4/5 px-3 py-2 text-xs">
              {explained.engine !== "built-in" && <span className="font-medium">{explained.engine}: </span>}{explained.text}
              {explained.note && <span className="text-muted-foreground"> ({explained.note})</span>}
            </div>
          )}

          <form
            className="flex flex-wrap gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              run();
            }}
          >
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="host:FIN-WS-04 type:LOGIN_FAIL -user:svc_* (empty: everything)" className="min-w-72 flex-[3] font-mono text-xs" aria-label="Search" spellCheck={false} />
            <NativeSelect value={range} onChange={(e) => setRange(e.target.value)} aria-label="Time range" className="w-44">
              {Object.entries(RANGES).map(([k, r]) => <option key={k} value={k}>{r.label}</option>)}
              {range === "custom" && <option value="custom">{`${fmt(params.from).slice(5, 16)} → ${fmt(params.to).slice(5, 16)}`}</option>}
            </NativeSelect>
            {!isClient && (
              <NativeSelect value={tenant} onChange={(e) => setTenant(e.target.value)} aria-label="Client" className="w-48">
                <option value="all">All clients</option>
                {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}{t.isTest ? " (test)" : ""}</option>)}
              </NativeSelect>
            )}
            <Button type="submit"><Search /> Search</Button>
            <Button type="button" variant="ghost" size="icon" onClick={() => setHelp((h) => !h)} aria-label="Search syntax"><HelpCircle /></Button>
          </form>

          {help && (
            <div className="grid gap-3 rounded-md border bg-muted/30 p-3 text-xs sm:grid-cols-2">
              <div className="flex flex-col gap-1">
                <p className="font-medium">Syntax</p>
                <p><code>field:value</code> terms side by side all match; <code>a OR b</code> either; <code>-field:value</code> or <code>NOT</code> excludes.</p>
                <p><code>*</code> is a wildcard: <code>process:*powershell*</code>. Quote values with spaces: <code>cmd:&quot;net user&quot;</code>.</p>
                <p><code>port:&gt;1024</code> compares numbers; <code>ip:1.2.3.4,5.6.7.8</code> any of a list; <code>hash:*</code> has a value, <code>-case:*</code> has none.</p>
                <p>A bare word or <code>&quot;phrase&quot;</code> searches everywhere in the event, raw fields included.</p>
              </div>
              <div className="flex flex-wrap content-start gap-1">
                {FIELDS.map((f) => (
                  <button key={f.key} type="button" className="rounded border bg-background px-1.5 py-0.5 font-mono hover:bg-accent" title={`${f.label}, e.g. ${f.example}`} onClick={() => setQ((cur) => `${cur.trim()} ${f.key}:`.trim())}>
                    {f.key}
                  </button>
                ))}
              </div>
            </div>
          )}

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <Bookmark className="size-3.5 text-muted-foreground" />
            {saved.length === 0 && <span className="text-muted-foreground">No saved searches yet.</span>}
            {saved.map((s) => (
              <span key={s.id} className="inline-flex items-center gap-1 rounded-full border px-2 py-0.5">
                <Link href={hrefFor({ q: s.query, range: s.range, tenant: isClient ? params.tenant : (s.tenant ?? "all") })} className="hover:underline" title={`${s.query || "everything"} · ${s.tenantName ?? (isClient ? "" : "all clients")} · saved by ${s.owner}`}>
                  {s.name}
                </Link>
                {s.shared && <Badge variant="soft" className="h-4 px-1 text-[10px]">shared</Badge>}
                {s.mine && <DeleteSaved id={s.id} />}
              </span>
            ))}
            <Button size="sm" variant="ghost" className="h-6 px-2 text-xs" onClick={() => setSaving(true)}><Plus /> Save this search</Button>
            <Button size="sm" variant="ghost" className="ml-auto h-6 px-2 text-xs" asChild>
              <a href={exportHref}><Download /> Export CSV</a>
            </Button>
          </div>
        </CardContent>
      </Card>

      {error && <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-sm text-destructive">{error}</div>}

      {result && (
        <>
          <Card>
            <CardHeader className="pb-0">
              <CardTitle className="flex flex-wrap items-baseline gap-2 text-base">
                {result.total.toLocaleString("en-IN")} event{result.total === 1 ? "" : "s"}
                <span className="text-xs font-normal text-muted-foreground">
                  {fmt(result.from)} → {fmt(result.to)} UTC · {result.ms} ms
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {result.total > 0 ? (
                <Histogram bars={result.histogram} bucketSeconds={result.bucketSeconds} from={result.from} to={result.to} onPick={(from, to) => router.push(hrefFor({ q, range: "custom", from, to, tenant }))} />
              ) : (
                <p className="py-6 text-center text-sm text-muted-foreground">Nothing matches in this window. Widen the time range or remove a filter.</p>
              )}
            </CardContent>
          </Card>

          {result.total > 0 && (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-[260px_minmax(0,1fr)]">
              <Card className="h-fit">
                <CardContent className="flex flex-col gap-4 text-xs">
                  {result.facets.map((f) => (
                    <div key={f.key} className="flex flex-col gap-1">
                      <p className="font-medium text-muted-foreground">{f.label}</p>
                      {f.values.map((v) => (
                        <div key={v.value} className="group flex items-center gap-1">
                          <button
                            type="button"
                            className="min-w-0 flex-1 truncate text-left hover:underline"
                            title={`Only ${v.label}`}
                            onClick={() => {
                              if (f.key !== "client") return addFilter(f.key, v.value);
                              setTenant(v.value);
                              router.push(hrefFor({ q: params.q, range: params.range, from: params.from, to: params.to, tenant: v.value }));
                            }}
                          >
                            {v.label}
                          </button>
                          <span className="tabular-nums text-muted-foreground">{v.n.toLocaleString("en-IN")}</span>
                          {f.key !== "client" && (
                            <>
                              <button type="button" className="opacity-0 group-hover:opacity-100" title={`Only ${v.label}`} aria-label={`Only ${v.label}`} onClick={() => addFilter(f.key, v.value)}><Plus className="size-3" /></button>
                              <button type="button" className="opacity-0 group-hover:opacity-100" title={`Not ${v.label}`} aria-label={`Not ${v.label}`} onClick={() => addFilter(f.key, v.value, true)}><Minus className="size-3" /></button>
                            </>
                          )}
                        </div>
                      ))}
                    </div>
                  ))}
                </CardContent>
              </Card>

              <Card className="min-w-0">
                <CardContent className="flex flex-col">
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b text-left text-muted-foreground">
                          <th className="w-5" />
                          <th className="px-2 py-1.5 font-medium whitespace-nowrap">Time (UTC)</th>
                          {showClient && <th className="px-2 py-1.5 font-medium">Client</th>}
                          <th className="px-2 py-1.5 font-medium">Type</th>
                          <th className="px-2 py-1.5 font-medium">Host</th>
                          <th className="px-2 py-1.5 font-medium">Account</th>
                          <th className="px-2 py-1.5 font-medium">Details</th>
                        </tr>
                      </thead>
                      <tbody>
                        {rows.map((r) => (
                          <React.Fragment key={`${r.id}:${r.timestamp}`}>
                            <tr className="cursor-pointer border-b align-top hover:bg-muted/40" onClick={() => setOpen((o) => (o === r.id ? null : r.id))}>
                              <td className="py-1.5 pl-1">{open === r.id ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}</td>
                              <td className="px-2 py-1.5 font-mono whitespace-nowrap">{fmt(r.timestamp)}</td>
                              {showClient && <td className="max-w-32 truncate px-2 py-1.5">{r.tenantId ? (tenantName.get(r.tenantId) ?? "—") : "Internal"}</td>}
                              <td className="px-2 py-1.5 whitespace-nowrap">
                                {r.eventType}
                                <div className="text-[10px] text-muted-foreground">{r.platform ?? r.source}</div>
                              </td>
                              <td className="max-w-40 truncate px-2 py-1.5 font-mono">{r.hostName ?? "—"}</td>
                              <td className="max-w-32 truncate px-2 py-1.5 font-mono">{r.userName ?? "—"}</td>
                              <td className="max-w-md truncate px-2 py-1.5 font-mono" title={summary(r)}>
                                {r.caseId && <Badge variant="outline" className="mr-1 h-4 px-1 text-[10px]">case</Badge>}
                                {summary(r)}
                              </td>
                            </tr>
                            {open === r.id && (
                              <tr className="border-b bg-muted/20">
                                <td />
                                <td colSpan={showClient ? 6 : 5} className="px-2 py-2">
                                  <EventDetail row={r} onFilter={addFilter} />
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="flex items-center justify-between pt-3 text-xs text-muted-foreground">
                    <span>Showing {rows.length.toLocaleString("en-IN")} of {result.total.toLocaleString("en-IN")}, newest first</span>
                    {next && (
                      <Button size="sm" variant="outline" onClick={() => more.mutate()} disabled={more.isPending}>
                        {more.isPending && <Loader2 className="animate-spin" />} Load older
                      </Button>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </>
      )}

      <SaveDialog open={saving} onOpenChange={setSaving} query={params.q} range={params.range === "custom" ? "24h" : params.range} tenant={params.tenant} isClient={isClient} />
    </div>
  );
}

const DETAIL_FIELDS: Array<[string, string, keyof Row]> = [
  ["host", "Host", "hostName"],
  ["user", "Account", "userName"],
  ["src", "Source IP", "sourceIp"],
  ["dst", "Destination IP", "destIp"],
  ["port", "Port", "destPort"],
  ["process", "Process", "processName"],
  ["cmd", "Command line", "commandLine"],
  ["file", "File", "filePath"],
  ["hash", "Hash", "fileHash"],
  ["type", "Event type", "eventType"],
  ["source", "Log source", "source"],
  ["platform", "Product", "platform"],
  ["severity", "Severity hint", "severityHint"],
];

function EventDetail({ row, onFilter }: { row: Row; onFilter: (field: string, value: string, negate?: boolean) => void }) {
  const detail = useMutation({ mutationFn: () => unwrap(eventDetailAction(row.id, row.timestamp)) });
  const { mutate } = detail;
  React.useEffect(() => mutate(), [mutate]);
  const full = detail.data;
  return (
    <div className="flex flex-col gap-2">
      <div className="grid gap-x-4 gap-y-1 sm:grid-cols-2">
        {DETAIL_FIELDS.filter(([, , k]) => row[k] != null && row[k] !== "").map(([field, label, k]) => (
          <div key={field} className="group flex min-w-0 items-baseline gap-2">
            <span className="w-24 shrink-0 text-muted-foreground">{label}</span>
            <span className="min-w-0 font-mono break-all">{String(row[k])}</span>
            <button type="button" className="opacity-0 group-hover:opacity-100" aria-label={`Only ${label}`} onClick={() => onFilter(field, String(row[k]))}><Plus className="size-3" /></button>
            <button type="button" className="opacity-0 group-hover:opacity-100" aria-label={`Not ${label}`} onClick={() => onFilter(field, String(row[k]), true)}><Minus className="size-3" /></button>
          </div>
        ))}
        {full?.integrationName && (
          <div className="flex items-baseline gap-2"><span className="w-24 shrink-0 text-muted-foreground">Client tool</span><span>{full.integrationName}</span></div>
        )}
        {full?.geo && (
          <div className="flex items-baseline gap-2"><span className="w-24 shrink-0 text-muted-foreground">Location</span><span>{full.geo}</span></div>
        )}
        {row.caseId && (
          <div className="flex items-baseline gap-2"><span className="w-24 shrink-0 text-muted-foreground">Case</span><Link className="underline" href={`/cases/${row.caseId}`}>Open the case</Link></div>
        )}
      </div>
      {detail.isPending && <p className="flex items-center gap-1 text-muted-foreground"><Loader2 className="size-3 animate-spin" /> Loading the full event…</p>}
      {detail.isError && <p className="text-destructive">{(detail.error as Error).message}</p>}
      {full && (full.metadata != null || full.ocsf != null) && (
        <details>
          <summary className="cursor-pointer text-muted-foreground">Raw event (as the tool sent it, and in OCSF)</summary>
          <JsonView value={{ raw: full.metadata, ocsf: full.ocsf }} className="mt-1 max-h-96" />
        </details>
      )}
    </div>
  );
}

function DeleteSaved({ id }: { id: string }) {
  const router = useRouter();
  const del = useMutation({
    mutationFn: () => unwrap(deleteSearchAction(id)),
    onSuccess: () => router.refresh(),
    onError: (err: Error) => toast.error(err.message),
  });
  return (
    <button type="button" aria-label="Delete saved search" className="text-muted-foreground hover:text-destructive" onClick={() => del.mutate()} disabled={del.isPending}>
      <Trash2 className="size-3" />
    </button>
  );
}

function SaveDialog({ open, onOpenChange, query, range, tenant, isClient }: { open: boolean; onOpenChange: (o: boolean) => void; query: string; range: string; tenant: string; isClient: boolean }) {
  const router = useRouter();
  const [name, setName] = React.useState("");
  const [shared, setShared] = React.useState(false);
  const save = useMutation({
    mutationFn: () => unwrap(saveSearchAction({ name, query, range, tenant: tenant === "all" ? null : tenant, shared })),
    onSuccess: () => {
      toast.success("Saved");
      onOpenChange(false);
      setName("");
      router.refresh();
    },
    onError: (err: Error) => toast.error(err.message),
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Save this search</DialogTitle>
          <DialogDescription className="font-mono text-xs break-all">{query || "(everything)"} · {RANGES[range as RangeKey]?.label ?? range}</DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="saved-name">Name</Label>
            <Input id="saved-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={120} placeholder="Failed sign-ins from outside India" />
          </div>
          <div className="flex items-center gap-2">
            <Switch id="saved-shared" checked={shared} onCheckedChange={setShared} />
            <Label htmlFor="saved-shared">{isClient ? "Share with my organisation's users" : "Share with the SOC"}</Label>
          </div>
        </div>
        <DialogFooter>
          <Button onClick={() => save.mutate()} disabled={!name.trim() || save.isPending}>
            {save.isPending && <Loader2 className="animate-spin" />} Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

