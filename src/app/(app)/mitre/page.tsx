import Link from "next/link";
import { Crosshair, Layers, Radar, ShieldCheck } from "lucide-react";
import type { CaseSource } from "@prisma/client";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { caseScope } from "@/lib/access";
import { detectionCapabilities } from "@/lib/mitre/coverage";
import { CASE_SOURCE_LABEL } from "@/lib/cases/labels";
import { cn } from "@/lib/utils";
import { StatTile } from "@/components/dashboard/stat-tile";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

// Sequential single-hue ramp (dataviz reference palette, blue 150→650) for
// "observed case count" — bucketed so small counts stay distinguishable.
// Cells at step 400+ switch to light ink to keep labels legible.
const BUCKETS = [
  { min: 1, max: 1, bg: "#b7d3f6", ink: "text-foreground", label: "1" },
  { min: 2, max: 3, bg: "#86b6ef", ink: "text-foreground", label: "2–3" },
  { min: 4, max: 6, bg: "#3987e5", ink: "text-white", label: "4–6" },
  { min: 7, max: 12, bg: "#256abf", ink: "text-white", label: "7–12" },
  { min: 13, max: Infinity, bg: "#104281", ink: "text-white", label: "13+" },
];

function bucketFor(count: number) {
  return BUCKETS.find((b) => count >= b.min && count <= b.max);
}

export default async function MitrePage() {
  const user = await pageGuard("mitre.view");
  const scope = await caseScope(user);
  const [tactics, mappings] = await Promise.all([
    db.mitreTactic.findMany({
      include: { techniques: { orderBy: { id: "asc" } } },
    }),
    db.caseMitreTechnique.findMany({
      where: { case: scope },
      select: { techniqueId: true, case: { select: { sourceType: true } } },
    }),
  ]);

  // Catalog order (Recon → Impact) rather than tactic-ID order.
  const tacticOrder = ["TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006", "TA0007", "TA0008", "TA0009", "TA0011", "TA0010", "TA0040"];
  tactics.sort((a, b) => tacticOrder.indexOf(a.id) - tacticOrder.indexOf(b.id));

  const observed = new Map<string, { total: number; bySource: Partial<Record<CaseSource, number>> }>();
  for (const m of mappings) {
    const entry = observed.get(m.techniqueId) ?? { total: 0, bySource: {} };
    entry.total++;
    entry.bySource[m.case.sourceType] = (entry.bySource[m.case.sourceType] ?? 0) + 1;
    observed.set(m.techniqueId, entry);
  }

  const capabilities = detectionCapabilities();
  const detectableBy = new Map<string, string[]>();
  for (const c of capabilities) {
    const list = detectableBy.get(c.techniqueId) ?? [];
    const label = `${c.module}: ${c.rule}`;
    if (!list.includes(label)) list.push(label);
    detectableBy.set(c.techniqueId, list);
  }

  const allTechniques = tactics.flatMap((t) => t.techniques);
  const detectableCount = allTechniques.filter((t) => detectableBy.has(t.id)).length;
  const observedCount = allTechniques.filter((t) => observed.has(t.id)).length;
  const tacticsCovered = tactics.filter((t) => t.techniques.some((x) => detectableBy.has(x.id) || observed.has(x.id))).length;

  const topObserved = allTechniques
    .filter((t) => observed.has(t.id))
    .map((t) => ({ technique: t, tactic: tactics.find((x) => x.id === t.tacticId)!, ...observed.get(t.id)! }))
    .sort((a, b) => b.total - a.total);

  if (allTechniques.length === 0) {
    return (
      <Card>
        <CardContent className="py-16 text-center text-sm text-muted-foreground">
          The MITRE ATT&amp;CK reference set hasn&apos;t been seeded yet — run <code>npm run db:seed</code>.
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="Techniques in reference set" value={allTechniques.length} icon={Layers} />
        <StatTile label="Detectable by HELIOS rules" value={detectableCount} icon={ShieldCheck} />
        <StatTile label="Observed in cases" value={observedCount} icon={Radar} />
        <StatTile label="Tactics covered" value={`${tacticsCovered}/${tactics.length}`} icon={Crosshair} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Coverage matrix</CardTitle>
          <CardDescription>
            Shading = number of cases mapped to the technique across all four sources.
            <span className="ml-1 inline-flex items-center gap-1"><ShieldCheck className="inline size-3.5" /> = a HELIOS rule can detect it.</span>{" "}
            Hover a cell for detail; click to open its cases.
          </CardDescription>
          <div className="flex flex-wrap items-center gap-3 pt-2 text-xs text-muted-foreground" aria-label="Legend">
            <span className="flex items-center gap-1.5">
              <span className="size-3 rounded-sm border bg-card" /> 0 cases
            </span>
            {BUCKETS.map((b) => (
              <span key={b.label} className="flex items-center gap-1.5">
                <span className="size-3 rounded-sm" style={{ background: b.bg }} /> {b.label}
              </span>
            ))}
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto pb-2">
            <div className="grid min-w-[1960px] grid-cols-[repeat(14,minmax(0,1fr))] gap-2">
              {tactics.map((tactic) => {
                const detectable = tactic.techniques.filter((t) => detectableBy.has(t.id)).length;
                return (
                  <div key={tactic.id} className="flex flex-col gap-1">
                    <div className="mb-1 min-h-12 border-b pb-2">
                      <p className="text-xs font-semibold leading-tight">{tactic.name}</p>
                      <p className="text-[11px] text-muted-foreground tabular-nums">
                        {tactic.id} · {detectable}/{tactic.techniques.length} detectable
                      </p>
                    </div>
                    {tactic.techniques.map((t) => {
                      const obs = observed.get(t.id);
                      const bucket = obs ? bucketFor(obs.total) : undefined;
                      const rules = detectableBy.get(t.id);
                      const tooltip = [
                        `${t.id} ${t.name}`,
                        obs
                          ? `${obs.total} case(s): ${Object.entries(obs.bySource).map(([s, n]) => `${CASE_SOURCE_LABEL[s as CaseSource]} ${n}`).join(", ")}`
                          : "Not observed in any case",
                        rules ? `Detectable by: ${rules.join("; ")}` : "No HELIOS rule emits this technique",
                      ].join("\n");
                      const className = cn(
                        "rounded-md border px-1.5 py-1 text-[11px] leading-tight",
                        bucket ? ["border-transparent", bucket.ink] : "bg-card",
                        obs && "transition-shadow hover:ring-2 hover:ring-ring/50",
                        t.isSubtechnique && "ml-2",
                      );
                      const body = (
                        <>
                          <span className="flex items-start justify-between gap-1">
                            <span className="font-mono opacity-80">{t.id}</span>
                            {rules && <ShieldCheck className="size-3 shrink-0" aria-hidden />}
                          </span>
                          <span className="line-clamp-2">{t.name}</span>
                          {obs && <span className="font-semibold tabular-nums">{obs.total}</span>}
                        </>
                      );
                      return obs ? (
                        <Link
                          key={t.id}
                          href={`/cases?status=all&technique=${t.id}`}
                          title={tooltip}
                          aria-label={tooltip}
                          className={className}
                          style={{ background: bucket?.bg }}
                        >
                          {body}
                        </Link>
                      ) : (
                        <div key={t.id} title={tooltip} className={className}>
                          {body}
                        </div>
                      );
                    })}
                  </div>
                );
              })}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Observed techniques</CardTitle>
          <CardDescription>Table view of the matrix&apos;s shaded cells, by case source.</CardDescription>
        </CardHeader>
        <CardContent>
          {topObserved.length === 0 ? (
            <p className="text-sm text-muted-foreground">No cases are mapped to ATT&amp;CK techniques yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Technique</TableHead>
                  <TableHead>Tactic</TableHead>
                  <TableHead className="text-right">Cases</TableHead>
                  <TableHead>By source</TableHead>
                  <TableHead>Detectable by</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {topObserved.map(({ technique, tactic, total, bySource }) => (
                  <TableRow key={technique.id}>
                    <TableCell>
                      <Link href={`/cases?status=all&technique=${technique.id}`} className="hover:underline">
                        <span className="font-mono text-xs text-muted-foreground">{technique.id}</span> {technique.name}
                      </Link>
                    </TableCell>
                    <TableCell className="text-xs">{tactic.name}</TableCell>
                    <TableCell className="text-right tabular-nums">{total}</TableCell>
                    <TableCell className="text-xs">
                      {Object.entries(bySource).map(([s, n]) => `${CASE_SOURCE_LABEL[s as CaseSource]} ${n}`).join(" · ")}
                    </TableCell>
                    <TableCell className="max-w-xs text-xs text-muted-foreground">
                      {detectableBy.get(technique.id)?.join("; ") ?? "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
