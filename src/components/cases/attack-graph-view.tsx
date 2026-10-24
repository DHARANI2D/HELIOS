"use client";

import * as React from "react";
import Link from "next/link";
import type { Core, ElementDefinition } from "cytoscape";
import type { CaseSeverity } from "@prisma/client";

import { useChartTokens } from "@/lib/chart-theme";
import { SEVERITY_CHART_COLOR, SEVERITY_LABEL } from "@/lib/severity";
import type { EntityType } from "@/lib/cases/attack-graph";

export interface ViewCase {
  id: string;
  title: string;
  severity: CaseSeverity;
  createdAt: string;
  tenantName: string | null;
}

export interface ViewEntity {
  key: string;
  type: EntityType;
  value: string;
  malicious: boolean;
  caseIds: string[];
}

// Categorical slots in fixed order, one per entity type; cases are neutral
// squares ringed in their severity's status color.
const TYPES: EntityType[] = ["host", "user", "ip", "domain", "url", "hash", "email", "agent"];
export const ENTITY_LABEL: Record<EntityType, string> = { host: "Host", user: "Account", ip: "IP address", domain: "Domain", url: "URL", hash: "File hash", email: "Email address", agent: "AI agent" };

function short(value: string) {
  return value.length > 28 ? `${value.slice(0, 12)}…${value.slice(-12)}` : value;
}

export function AttackGraphView({ cases, entities }: { cases: ViewCase[]; entities: ViewEntity[] }) {
  const t = useChartTokens();
  const containerRef = React.useRef<HTMLDivElement>(null);
  const [selected, setSelected] = React.useState<{ kind: "case"; item: ViewCase } | { kind: "entity"; item: ViewEntity } | null>(null);
  const caseById = React.useMemo(() => new Map(cases.map((c) => [c.id, c])), [cases]);
  const entityByKey = React.useMemo(() => new Map(entities.map((e) => [e.key, e])), [entities]);
  const color = React.useCallback((type: EntityType) => t.series[TYPES.indexOf(type)], [t]);

  React.useEffect(() => {
    let cy: Core | undefined;
    let cancelled = false;
    // cytoscape touches window at import time — load it on the client only.
    import("cytoscape").then(({ default: cytoscape }) => {
      if (cancelled || !containerRef.current) return;
      const elements: ElementDefinition[] = [
        ...cases.map((c) => ({ data: { id: `case:${c.id}`, label: short(c.title), fill: t.surface, ring: SEVERITY_CHART_COLOR[c.severity].light, kind: "case" } })),
        ...entities.map((e) => ({ data: { id: e.key, label: short(e.value), fill: color(e.type), ring: e.malicious ? t.ink : color(e.type), kind: "entity" } })),
        ...entities.flatMap((e) => e.caseIds.map((id) => ({ data: { id: `${e.key}->${id}`, source: e.key, target: `case:${id}` } }))),
      ];
      cy = cytoscape({
        container: containerRef.current,
        elements,
        wheelSensitivity: 0.2,
        layout: { name: "cose", animate: false, padding: 24, nodeRepulsion: () => 9000, idealEdgeLength: () => 70 },
        style: [
          {
            selector: "node",
            style: {
              "background-color": "data(fill)",
              "border-color": "data(ring)",
              "border-width": 2,
              label: "data(label)",
              "font-size": 9,
              color: t.inkSecondary,
              "text-valign": "bottom",
              "text-margin-y": 4,
              width: 16,
              height: 16,
            },
          },
          { selector: 'node[kind = "case"]', style: { shape: "round-rectangle", width: 20, height: 20, "border-width": 3 } },
          { selector: "node:selected", style: { "border-width": 4, "border-color": t.ink } },
          { selector: "edge", style: { width: 1.5, "line-color": t.baseline, "curve-style": "bezier" } },
        ],
      });
      cy.on("tap", "node", (evt) => {
        const id = evt.target.id() as string;
        if (id.startsWith("case:")) {
          const c = caseById.get(id.slice(5));
          setSelected(c ? { kind: "case", item: c } : null);
        } else {
          const e = entityByKey.get(id);
          setSelected(e ? { kind: "entity", item: e } : null);
        }
      });
      cy.on("tap", (evt) => {
        if (evt.target === cy) setSelected(null);
      });
    });
    return () => {
      cancelled = true;
      cy?.destroy();
    };
  }, [cases, entities, t, color, caseById, entityByKey]);

  const present = TYPES.filter((type) => entities.some((e) => e.type === type));
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-muted-foreground" aria-label="Legend">
        <span className="flex items-center gap-1.5"><span className="size-2.5 rounded-[3px] border-2" style={{ borderColor: SEVERITY_CHART_COLOR.HIGH.light }} /> Case (ring = severity)</span>
        {present.map((type) => (
          <span key={type} className="flex items-center gap-1.5">
            <span className="size-2.5 rounded-full" style={{ background: color(type) }} /> {ENTITY_LABEL[type]}
          </span>
        ))}
        <span className="flex items-center gap-1.5"><span className="size-2.5 rounded-full border-2" style={{ borderColor: t.ink }} /> Known malicious</span>
      </div>
      <div ref={containerRef} className="h-[520px] w-full rounded-md border bg-muted/20" role="img" aria-label="Graph of cases and the entities they share; the tables below list the same links" />
      {selected?.kind === "case" ? (
        <div className="rounded-md border p-3 text-sm">
          <p className="text-xs text-muted-foreground">Case · {SEVERITY_LABEL[selected.item.severity]} · {new Date(selected.item.createdAt).toLocaleString()}{selected.item.tenantName ? ` · ${selected.item.tenantName}` : ""}</p>
          <Link href={`/cases/${selected.item.id}`} className="font-medium hover:underline">{selected.item.title}</Link>
        </div>
      ) : selected?.kind === "entity" ? (
        <div className="rounded-md border p-3 text-sm">
          <p className="text-xs text-muted-foreground">{ENTITY_LABEL[selected.item.type]}{selected.item.malicious ? " · known malicious" : ""} · in {selected.item.caseIds.length} cases</p>
          <p className="font-mono text-xs break-all">{selected.item.value}</p>
          <ul className="mt-2 space-y-0.5 text-xs">
            {selected.item.caseIds.map((id) => caseById.get(id)).filter((c): c is ViewCase => !!c).map((c) => (
              <li key={c.id}><Link href={`/cases/${c.id}`} className="hover:underline">{c.title}</Link></li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">Click a case or an entity for details. Scroll to zoom, drag to pan.</p>
      )}
    </div>
  );
}
