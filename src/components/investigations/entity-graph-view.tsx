"use client";

import * as React from "react";
import cytoscape, { type Core } from "cytoscape";

import type { EntityGraph } from "@/lib/investigations/types";

// Raw cytoscape.js — there's no maintained React wrapper for the current
// major version, so this mounts/tears down an instance imperatively via a
// ref, matching how signal-fusion's GraphViewer.tsx used cytoscape too.

const NODE_COLOR: Record<string, string> = {
  process: "#2a78d6", // categorical slot 1 (dataviz skill palette)
  ip: "#1baf7a", // slot 3
  file: "#008300", // slot 6
};

export function EntityGraphView({ graph }: { graph: EntityGraph }) {
  const containerRef = React.useRef<HTMLDivElement>(null);
  const cyRef = React.useRef<Core | null>(null);

  React.useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      elements: [
        ...graph.nodes.map((n) => ({
          data: { id: n.id, label: n.label, type: n.type },
        })),
        ...graph.edges.map((e, i) => ({
          data: { id: `e${i}`, source: e.source, target: e.target, label: e.relation },
        })),
      ],
      style: [
        {
          selector: "node",
          style: {
            "background-color": (ele) => NODE_COLOR[ele.data("type")] ?? "#898781",
            label: "data(label)",
            color: "#0b0b0b",
            "font-size": 10,
            "text-valign": "bottom",
            "text-margin-y": 4,
            width: 24,
            height: 24,
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#c3c2b7",
            "target-arrow-color": "#c3c2b7",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": 8,
            color: "#52514e",
          },
        },
      ],
      layout: { name: "breadthfirst", directed: true, spacingFactor: 1.2 },
    });

    cyRef.current = cy;
    return () => cy.destroy();
  }, [graph]);

  if (graph.nodes.length === 0) {
    return (
      <p className="py-10 text-center text-sm text-muted-foreground">
        No entity graph — this investigation has no linked telemetry.
      </p>
    );
  }

  return <div ref={containerRef} className="h-80 w-full rounded-md border" />;
}
