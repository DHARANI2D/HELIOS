import type { NormalizedEvent } from "@/lib/detection/types";
import type { EntityGraph, GraphNode, GraphEdge } from "./types";

// Ported from asip's graph/entity_graph.py EntityGraphBuilder (networkx) —
// reimplemented directly over Node maps/arrays rather than pulling in a
// graph library, since the original only ever used it to build then
// serialize a node-link structure (no traversal/algorithms were run on
// it). Runs over the same NormalizedEvent shape the detection engine
// uses, instead of asip's separate process/network/file event schema —
// one shared "what happened" representation for both modules.

function fileNodeId(path: string, hash?: string) {
  return hash ? `file_${hash}` : `file_${path.replace(/[:/\\]/g, "_")}`;
}

export function buildEntityGraph(events: NormalizedEvent[]): EntityGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];

  const sorted = [...events].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

  // host+process is the correlation key (our events don't carry PIDs
  // unless the raw log's metadata supplies one).
  const activeProcesses = new Map<string, string>();

  function processKey(host: string, process: string, pid?: unknown) {
    return `${host}::${process}::${pid ?? "nopid"}`;
  }

  function processNodeId(host: string, process: string, pid?: unknown) {
    return `proc_${host}_${process}_${pid ?? "nopid"}`.replace(/\s+/g, "_");
  }

  // Step 1: process nodes + SPAWNED edges
  for (const ev of sorted) {
    if (ev.source !== "ENDPOINT" || !ev.actor.process) continue;

    const host = (ev.metadata.hostname as string) ?? "unknown_host";
    const pid = ev.metadata.pid;
    const key = processKey(host, ev.actor.process, pid);
    const nodeId = processNodeId(host, ev.actor.process, pid);

    if (!nodes.has(nodeId)) {
      nodes.set(nodeId, {
        id: nodeId,
        type: "process",
        label: ev.actor.process,
        commandline: ev.actor.process,
        user: ev.actor.user ?? "",
        host,
        timestamp: ev.timestamp.toISOString(),
      });
    }
    activeProcesses.set(key, nodeId);

    const parentProcess = ev.metadata.parentProcess ?? ev.metadata.parent_process;
    if (typeof parentProcess === "string") {
      const parentKey = processKey(host, parentProcess, undefined);
      let parentNodeId = activeProcesses.get(parentKey);
      if (!parentNodeId) {
        parentNodeId = processNodeId(host, parentProcess, "parent");
        if (!nodes.has(parentNodeId)) {
          nodes.set(parentNodeId, {
            id: parentNodeId,
            type: "process",
            label: parentProcess,
            commandline: "[unobserved parent process]",
            user: "",
            host,
          });
        }
      }
      edges.push({ source: parentNodeId, target: nodeId, relation: "SPAWNED" });
    }
  }

  // Step 2: network + file correlation
  for (const ev of sorted) {
    const host = (ev.metadata.hostname as string) ?? "unknown_host";
    let procNodeId: string | undefined;

    if (ev.actor.process) {
      procNodeId = activeProcesses.get(processKey(host, ev.actor.process, ev.metadata.pid));
    }

    if (ev.source === "NETWORK" && ev.network.destIp && procNodeId) {
      const ipNodeId = `ip_${ev.network.destIp}`;
      if (!nodes.has(ipNodeId)) {
        nodes.set(ipNodeId, {
          id: ipNodeId,
          type: "ip",
          label: ev.network.destIp,
          port: ev.metadata.port,
        });
      }
      edges.push({ source: procNodeId, target: ipNodeId, relation: "CONNECTED_TO" });
    }

    const filePath = ev.metadata.file_path ?? ev.metadata.filePath;
    if (typeof filePath === "string" && procNodeId) {
      const hash = typeof ev.metadata.hash === "string" ? ev.metadata.hash : undefined;
      const fNodeId = fileNodeId(filePath, hash);
      const fileName = filePath.split(/[/\\]/).pop() ?? filePath;
      if (!nodes.has(fNodeId)) {
        nodes.set(fNodeId, { id: fNodeId, type: "file", label: fileName, path: filePath, hash: hash ?? "" });
      }
      edges.push({ source: procNodeId, target: fNodeId, relation: "CREATED" });
    }
  }

  return { nodes: [...nodes.values()], edges };
}
