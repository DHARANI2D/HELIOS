"use client";

import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, RotateCcw } from "lucide-react";
import { toast } from "sonner";

import { replayDeadLettersAction, setQuietLimitAction } from "@/app/(app)/integrations/actions";
import { formatRelative } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { NativeSelect } from "@/components/ui/native-select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

type State = "live" | "quiet" | "never" | "unwatched" | "stale";

export interface SourceRow {
  id: string;
  name: string;
  tenant: string | null;
  state: State;
  lastEventAt: string | null;
  lastHour: number;
  perHour7d: number;
  hours: number[];
  limitMinutes: number | null;
  setting: number | null;
  quietCaseId: string | null;
  via: string;
}

export interface DeadLetterRow {
  id: string;
  integration: string;
  reason: string;
  raw: string;
  createdAt: string;
}

const STATE: Record<State, { label: string; variant: "success" | "warning" | "destructive" | "outline" | "soft" }> = {
  live: { label: "live", variant: "success" },
  quiet: { label: "quiet", variant: "destructive" },
  stale: { label: "late", variant: "warning" },
  never: { label: "no data yet", variant: "outline" },
  unwatched: { label: "receiving", variant: "soft" },
};

const LIMITS: Array<[string, string]> = [
  ["", "Default"],
  ["30", "30 min"],
  ["60", "1 hour"],
  ["120", "2 hours"],
  ["360", "6 hours"],
  ["1440", "1 day"],
  ["0", "Never"],
];

function Spark({ hours }: { hours: number[] }) {
  const max = Math.max(1, ...hours);
  return (
    <div className="flex h-6 items-end gap-px" aria-label={`Events per hour over the last day: ${hours.join(", ")}`}>
      {hours.map((h, i) => (
        <span key={i} className={h ? "w-1 rounded-sm bg-primary/70" : "w-1 rounded-sm bg-muted"} style={{ height: `${h ? Math.max(12, (h / max) * 100) : 12}%` }} />
      ))}
    </div>
  );
}

function limitLabel(row: SourceRow) {
  if (row.limitMinutes === null) return row.setting === 0 ? "not watched" : "not watched (alert feed)";
  const m = row.limitMinutes;
  return `quiet after ${m >= 1440 ? `${m / 1440} day` : m >= 60 ? `${m / 60} h` : `${m} min`}${row.setting === null ? " (default)" : ""}`;
}

export function LogSources({ sources, deadLetters, queue, canManage, now }: { sources: SourceRow[]; deadLetters: DeadLetterRow[]; queue: { waiting: number; failed24h: number }; canManage: boolean; now: string }) {
  const router = useRouter();
  const nowDate = new Date(now);
  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed");
  const limit = useMutation({
    mutationFn: ({ id, value }: { id: string; value: string }) => setQuietLimitAction(id, value === "" ? null : Number(value)),
    onSuccess: () => router.refresh(),
    onError,
  });
  const replay = useMutation({
    mutationFn: (ids: string[]) => replayDeadLettersAction(ids),
    onSuccess: (r) => {
      toast.success(`${r.count} record${r.count === 1 ? "" : "s"} back on the queue`);
      router.refresh();
    },
    onError,
  });

  return (
    <div className="flex flex-col gap-4">
      <p className="text-xs text-muted-foreground">
        {queue.waiting ? `${queue.waiting} batch${queue.waiting === 1 ? "" : "es"} waiting in the ingest queue. ` : "The ingest queue is empty. "}
        {queue.failed24h ? `${queue.failed24h} failed in the last day (kept below). ` : ""}A source that goes quiet opens a case: attackers often stop logging first.
      </p>
      {sources.length === 0 ? (
        <p className="text-sm text-muted-foreground">No log sources yet: onboard a tool that sends data, set up its log collector, or issue a forwarder configuration.</p>
      ) : (
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Source</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Last 24 h</TableHead>
                <TableHead className="text-right">Last hour</TableHead>
                <TableHead className="text-right">Per hour (7 d)</TableHead>
                <TableHead>Silence limit</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sources.map((s) => (
                <TableRow key={s.id}>
                  <TableCell>
                    <p className="text-sm font-medium">{s.name}</p>
                    <p className="text-[11px] text-muted-foreground">{[s.tenant, s.via].filter(Boolean).join(" · ")}</p>
                  </TableCell>
                  <TableCell>
                    <Badge variant={STATE[s.state].variant}>{STATE[s.state].label}</Badge>
                    <p className="mt-0.5 text-[11px] text-muted-foreground">{s.lastEventAt ? `last ${formatRelative(s.lastEventAt, nowDate)}` : "—"}</p>
                    {s.quietCaseId && <Link href={`/cases/${s.quietCaseId}`} className="text-[11px] text-destructive hover:underline">Open case</Link>}
                  </TableCell>
                  <TableCell><Spark hours={s.hours} /></TableCell>
                  <TableCell className="text-right tabular-nums">{s.lastHour.toLocaleString()}</TableCell>
                  <TableCell className="text-right tabular-nums">{s.perHour7d > 0 && s.perHour7d < 0.1 ? "<0.1" : s.perHour7d.toLocaleString(undefined, { maximumFractionDigits: 1 })}</TableCell>
                  <TableCell className="text-xs">
                    {canManage ? (
                      <NativeSelect className="h-8 text-xs" aria-label={`Silence limit for ${s.name}`} value={s.setting === null ? "" : String(s.setting)} onChange={(e) => limit.mutate({ id: s.id, value: e.target.value })} disabled={limit.isPending}>
                        {LIMITS.map(([v, l]) => (
                          <option key={v} value={v}>{l}</option>
                        ))}
                      </NativeSelect>
                    ) : null}
                    <p className="mt-0.5 text-[11px] text-muted-foreground">{limitLabel(s)}</p>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {deadLetters.length > 0 && (
        <details className="rounded-md border p-3" open={deadLetters.length <= 5}>
          <summary className="cursor-pointer text-sm font-medium">Dead letters: {deadLetters.length} record{deadLetters.length === 1 ? "" : "s"} no mapper could read</summary>
          <p className="mt-1 text-[11px] text-muted-foreground">Kept as received. Fix the source or the mapping, then send them back through the queue.</p>
          <ul className="mt-2 flex flex-col gap-2">
            {deadLetters.map((d) => (
              <li key={d.id} className="rounded border bg-muted/30 p-2 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span><span className="font-medium">{d.integration}</span> · {d.reason} · {formatRelative(d.createdAt, nowDate)}</span>
                  {canManage && (
                    <Button size="sm" variant="ghost" className="h-6" onClick={() => replay.mutate([d.id])} disabled={replay.isPending}>
                      <RotateCcw /> Replay
                    </Button>
                  )}
                </div>
                <pre className="mt-1 max-h-20 overflow-hidden whitespace-pre-wrap break-all font-mono text-[10px] text-muted-foreground">{d.raw}</pre>
              </li>
            ))}
          </ul>
          {canManage && deadLetters.length > 1 && (
            <Button size="sm" variant="outline" className="mt-2" onClick={() => replay.mutate(deadLetters.map((d) => d.id))} disabled={replay.isPending}>
              {replay.isPending ? <Loader2 className="animate-spin" /> : <RotateCcw />} Replay all
            </Button>
          )}
        </details>
      )}
    </div>
  );
}
