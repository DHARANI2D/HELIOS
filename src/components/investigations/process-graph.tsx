"use client";

import * as React from "react";
import type { Core, ElementDefinition } from "cytoscape";

import type { GraphNode, GraphNodeType, EntityGraph } from "@/lib/investigations/graph";

// Categorical slots from the dataviz reference palette, in fixed order.
const TYPE_COLOR: Record<GraphNodeType, string> = {
  process: "#2a78d6",
  ip: "#eb6834",
  file: "#1baf7a",
  domain: "#6250d6",
};
const TYPE_LABEL: Record<GraphNodeType, string> = { process: "Process", ip: "Network destination", file: "File", domain: "DNS query" };

export function ProcessGraph({ graph }: { graph: EntityGraph & { truncated?: boolean; totalNodes?: number } }) {
  const containerRef = React.useRef<HTMLDivElement>(null);
  const [selected, setSelected] = React.useState<GraphNode | null>(null);

  React.useEffect(() => {
    let cy: Core | undefined;
    let cancelled = false;
    // cytoscape touches window at import time — load it on the client only.
    import("cytoscape").then(({ default: cytoscape }) => {
      if (cancelled || !containerRef.current) return;
      const byId = new Map(graph.nodes.map((n) => [n.id, n]));
      const elements: ElementDefinition[] = [
        ...graph.nodes.map((n) => ({
          data: {
            id: n.id,
            label: n.pid !== undefined ? `${n.label}\n${n.pid}` : n.label,
            color: TYPE_COLOR[n.type],
            border: n.observed ? TYPE_COLOR[n.type] : "#898781",
          },
        })),
        ...graph.edges.map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target, label: e.relation } })),
      ];
      const roots = graph.nodes.filter((n) => !graph.edges.some((e) => e.target === n.id && e.relation === "SPAWNED") && n.type === "process").map((n) => n.id);

      cy = cytoscape({
        container: containerRef.current,
        elements,
        wheelSensitivity: 0.2,
        layout: { name: "breadthfirst", directed: true, roots: roots.length ? roots : undefined, spacingFactor: 1.1, padding: 16 },
        style: [
          {
            selector: "node",
            style: {
              "background-color": "data(color)",
              "border-width": 2,
              "border-color": "data(border)",
              label: "data(label)",
              "text-wrap": "wrap",
              "font-size": 10,
              color: "#0b0b0b",
              "text-valign": "bottom",
              "text-margin-y": 4,
              width: 18,
              height: 18,
            },
          },
          { selector: "node:selected", style: { "border-width": 4, "border-color": "#0b0b0b" } },
          {
            selector: "edge",
            style: {
              width: 1.5,
              "line-color": "#c3c2b7",
              "target-arrow-color": "#c3c2b7",
              "target-arrow-shape": "triangle",
              "curve-style": "bezier",
              label: "data(label)",
              "font-size": 7,
              color: "#898781",
              "text-rotation": "autorotate",
            },
          },
        ],
      });
      cy.on("tap", "node", (evt) => setSelected(byId.get(evt.target.id()) ?? null));
      cy.on("tap", (evt) => {
        if (evt.target === cy) setSelected(null);
      });
    });
    return () => {
      cancelled = true;
      cy?.destroy();
    };
  }, [graph]);

  if (graph.nodes.length === 0) {
    return <p className="text-sm text-muted-foreground">No process, network, or file relationships could be built from these events.</p>;
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-3 text-xs text-muted-foreground" aria-label="Legend">
        {(Object.keys(TYPE_COLOR) as GraphNodeType[]).map((t) => (
          <span key={t} className="flex items-center gap-1.5">
            <span className="size-2.5 rounded-full" style={{ background: TYPE_COLOR[t] }} /> {TYPE_LABEL[t]}
          </span>
        ))}
        <span className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-full border-2" style={{ borderColor: "#898781" }} /> Unobserved parent
        </span>
        {graph.truncated && <span>Showing {graph.nodes.length} of {graph.totalNodes} nodes nearest the findings</span>}
      </div>
      <div ref={containerRef} className="h-[460px] w-full rounded-md border bg-muted/20" role="img" aria-label="Process lineage graph" />
      {selected ? (
        <dl className="grid gap-x-4 gap-y-1 rounded-md border p-3 text-xs sm:grid-cols-[max-content_1fr]">
          <dt className="text-muted-foreground">Type</dt>
          <dd>{TYPE_LABEL[selected.type]}</dd>
          <dt className="text-muted-foreground">Name</dt>
          <dd className="font-mono break-all">{selected.label}</dd>
          {selected.pid !== undefined && (<><dt className="text-muted-foreground">PID</dt><dd>{selected.pid}</dd></>)}
          {selected.host && (<><dt className="text-muted-foreground">Host</dt><dd>{selected.host}</dd></>)}
          {selected.user && (<><dt className="text-muted-foreground">User</dt><dd>{selected.user}</dd></>)}
          {selected.timestamp && (<><dt className="text-muted-foreground">Started</dt><dd>{selected.timestamp}</dd></>)}
          {selected.commandLine && (<><dt className="text-muted-foreground">Command line</dt><dd className="font-mono break-all">{selected.commandLine}</dd></>)}
          {selected.path && (<><dt className="text-muted-foreground">Path</dt><dd className="font-mono break-all">{selected.path}</dd></>)}
          {selected.hash && (<><dt className="text-muted-foreground">SHA-256</dt><dd className="font-mono break-all">{selected.hash}</dd></>)}
          {selected.port !== undefined && (<><dt className="text-muted-foreground">Port</dt><dd>{selected.port}</dd></>)}
        </dl>
      ) : (
        <p className="text-xs text-muted-foreground">Click a node for details. Scroll to zoom, drag to pan.</p>
      )}
    </div>
  );
}
