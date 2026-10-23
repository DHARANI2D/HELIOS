import type { UesEvent } from "@/lib/investigations/normalize";

// Port of asip's graph/entity_graph.py (networkx DiGraph → plain node/edge
// lists): process lineage (SPAWNED), outbound connections (CONNECTED_TO),
// dropped / loaded files (CREATED / LOADED), and DNS lookups (RESOLVED).

export type GraphNodeType = "process" | "ip" | "file" | "domain";

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  pid?: number;
  host?: string;
  user?: string;
  commandLine?: string;
  timestamp?: string;
  hash?: string;
  path?: string;
  port?: number;
  observed: boolean; // false for placeholder parents never seen launching
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: "SPAWNED" | "CONNECTED_TO" | "CREATED" | "LOADED" | "RESOLVED";
}

export interface EntityGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

const PROCESS_EVENTS = new Set(["process_create", "process", "process_rollup", "process_launch"]);
const NETWORK_EVENTS = new Set(["network_connect", "network"]);
const FILE_EVENTS = new Set(["file_create", "file", "file_create_stream_hash"]);

export function buildEntityGraph(events: UesEvent[]): EntityGraph {
  const sorted = [...events].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();
  const active = new Map<string, string>(); // `${host}|${pid}` -> node id

  const addEdge = (source: string, target: string, relation: GraphEdge["relation"]) => {
    edges.set(`${source}>${target}>${relation}`, { source, target, relation });
  };

  // Pass 1: process creations and lineage.
  for (const ev of sorted) {
    if (!PROCESS_EVENTS.has(ev.eventType) || !ev.processName || ev.processPid === undefined) continue;
    const host = ev.hostName ?? "unknown_host";
    const id = `proc:${host}:${ev.processName}:${ev.processPid}:${ev.timestamp.getTime()}`;
    nodes.set(id, {
      id,
      type: "process",
      label: ev.processName,
      pid: ev.processPid,
      host,
      user: ev.userName,
      commandLine: ev.commandLine,
      timestamp: ev.timestamp.toISOString(),
      hash: ev.fileHash,
      observed: true,
    });
    active.set(`${host}|${ev.processPid}`, id);

    if (ev.parentProcessName && ev.parentProcessPid !== undefined) {
      let parentId = active.get(`${host}|${ev.parentProcessPid}`);
      if (!parentId) {
        parentId = `proc:${host}:${ev.parentProcessName}:${ev.parentProcessPid}:parent`;
        if (!nodes.has(parentId)) {
          nodes.set(parentId, {
            id: parentId,
            type: "process",
            label: ev.parentProcessName,
            pid: ev.parentProcessPid,
            host,
            commandLine: "[unobserved parent process]",
            observed: false,
          });
        }
      }
      addEdge(parentId, id, "SPAWNED");
    }
  }

  // Pass 2: attach network / file / DNS activity to the acting process.
  for (const ev of sorted) {
    const host = ev.hostName ?? "unknown_host";
    let procId = ev.processPid !== undefined ? active.get(`${host}|${ev.processPid}`) : undefined;
    if (!procId) {
      if (ev.processPid === undefined || !ev.processName) continue;
      procId = `proc:${host}:${ev.processName}:${ev.processPid}:generic`;
      if (!nodes.has(procId)) {
        nodes.set(procId, { id: procId, type: "process", label: ev.processName, pid: ev.processPid, host, user: ev.userName, observed: true });
      }
    }

    if ((NETWORK_EVENTS.has(ev.eventType) || ev.dstIp) && ev.dstIp) {
      const ipId = `ip:${ev.dstIp}`;
      if (!nodes.has(ipId)) nodes.set(ipId, { id: ipId, type: "ip", label: ev.dstIp, port: ev.dstPort, observed: true });
      addEdge(procId, ipId, "CONNECTED_TO");
    } else if (ev.eventType === "dns_query" && ev.query) {
      const domainId = `domain:${ev.query.toLowerCase()}`;
      if (!nodes.has(domainId)) nodes.set(domainId, { id: domainId, type: "domain", label: ev.query.toLowerCase(), observed: true });
      addEdge(procId, domainId, "RESOLVED");
    } else if ((FILE_EVENTS.has(ev.eventType) || ev.eventType === "image_load") && ev.filePath) {
      const fileId = ev.fileHash ? `file:${ev.fileHash}` : `file:${ev.filePath.toLowerCase()}`;
      if (!nodes.has(fileId)) {
        nodes.set(fileId, {
          id: fileId,
          type: "file",
          label: ev.filePath.split(/[\\/]/).pop() ?? ev.filePath,
          path: ev.filePath,
          hash: ev.fileHash,
          observed: true,
        });
      }
      addEdge(procId, fileId, ev.eventType === "image_load" ? "LOADED" : "CREATED");
    }
  }

  return { nodes: [...nodes.values()], edges: [...edges.values()] };
}

// Ancestry chain (root → node) for narrating how a process came to run.
export function ancestry(graph: EntityGraph, nodeId: string): GraphNode[] {
  const parentOf = new Map<string, string>();
  for (const e of graph.edges) if (e.relation === "SPAWNED") parentOf.set(e.target, e.source);
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const chain: GraphNode[] = [];
  const seen = new Set<string>();
  let cur: string | undefined = nodeId;
  while (cur && !seen.has(cur)) {
    seen.add(cur);
    const node = byId.get(cur);
    if (node) chain.unshift(node);
    cur = parentOf.get(cur);
  }
  return chain;
}
