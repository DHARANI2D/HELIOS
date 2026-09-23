import { describe, it, expect } from "vitest";

import { buildEntityGraph } from "./entity-graph";
import type { NormalizedEvent } from "@/lib/detection/types";

let seq = 0;
function ev(partial: Partial<NormalizedEvent>): NormalizedEvent {
  seq += 1;
  return {
    id: `ev-${seq}`,
    timestamp: new Date(),
    source: "ENDPOINT",
    eventType: "PROCESS_START",
    actor: {},
    network: {},
    metadata: {},
    ...partial,
  };
}

describe("buildEntityGraph", () => {
  it("returns an empty graph for no events", () => {
    const graph = buildEntityGraph([]);
    expect(graph.nodes).toHaveLength(0);
    expect(graph.edges).toHaveLength(0);
  });

  it("creates a process node for an endpoint event", () => {
    const graph = buildEntityGraph([ev({ actor: { process: "powershell.exe", user: "admin" }, metadata: { hostname: "dc-01" } })]);
    expect(graph.nodes).toHaveLength(1);
    expect(graph.nodes[0].type).toBe("process");
    expect(graph.nodes[0].label).toBe("powershell.exe");
  });

  it("links a child process to its parent with a SPAWNED edge, synthesizing an unobserved-parent node", () => {
    const graph = buildEntityGraph([
      ev({
        actor: { process: "mimikatz.exe", user: "admin" },
        metadata: { hostname: "dc-01", parentProcess: "powershell.exe" },
      }),
    ]);
    expect(graph.nodes).toHaveLength(2);
    expect(graph.edges).toHaveLength(1);
    expect(graph.edges[0].relation).toBe("SPAWNED");

    const parentNode = graph.nodes.find((n) => n.label === "powershell.exe");
    expect(parentNode?.commandline).toBe("[unobserved parent process]");
  });

  it("links a process to a network destination with a CONNECTED_TO edge", () => {
    const graph = buildEntityGraph([
      ev({
        actor: { process: "beacon.exe" },
        source: "NETWORK",
        network: { destIp: "185.220.101.5" },
        metadata: { hostname: "ws-01", port: 4444 },
      }),
    ]);
    // NETWORK-source events aren't themselves process nodes (only ENDPOINT
    // events create process nodes) — with no prior ENDPOINT event for this
    // process, there's no active process to link the connection to.
    expect(graph.nodes.filter((n) => n.type === "ip")).toHaveLength(0);
  });

  it("links a known active process to a network destination when both events reference it", () => {
    const graph = buildEntityGraph([
      ev({ source: "ENDPOINT", actor: { process: "beacon.exe" }, metadata: { hostname: "ws-01" } }),
      ev({
        source: "NETWORK",
        actor: { process: "beacon.exe" },
        network: { destIp: "185.220.101.5" },
        metadata: { hostname: "ws-01", port: 4444 },
      }),
    ]);
    const ipNode = graph.nodes.find((n) => n.type === "ip");
    expect(ipNode?.label).toBe("185.220.101.5");
    expect(graph.edges.some((e) => e.relation === "CONNECTED_TO")).toBe(true);
  });

  it("deduplicates the same process appearing in multiple events", () => {
    const graph = buildEntityGraph([
      ev({ actor: { process: "explorer.exe" }, metadata: { hostname: "ws-01" } }),
      ev({ actor: { process: "explorer.exe" }, metadata: { hostname: "ws-01" } }),
    ]);
    expect(graph.nodes.filter((n) => n.label === "explorer.exe")).toHaveLength(1);
  });
});
