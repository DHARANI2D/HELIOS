import networkx as nx
from typing import List, Dict, Any, Optional
from datetime import datetime

class EntityGraphBuilder:
    def build_graph(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Builds a forensic correlation graph from list of normalized events.
        Correlates processes, files, registry keys, and network targets.
        """
        G = nx.DiGraph()

        # Sort events chronologically to process flows correctly
        sorted_events = sorted(events, key=lambda e: e.get("timestamp") or datetime.min)

        # We keep track of active processes by (host_name, pid) -> node_id to correlate events accurately
        active_processes: Dict[tuple, str] = {}
        
        # Helper to generate unique node IDs
        def make_process_id(host, name, pid, timestamp):
            ts_str = timestamp.strftime("%H%M%S") if isinstance(timestamp, datetime) else "000000"
            return f"proc_{host}_{name}_{pid}_{ts_str}"

        # Step 1: Create nodes for all processes
        for ev in sorted_events:
            ev_type = ev.get("event_type")
            host = ev.get("host_name") or "unknown_host"
            pid = ev.get("process_pid")
            proc_name = ev.get("process_name")
            timestamp = ev.get("timestamp")
            
            # Map process creations
            if ev_type in ("process", "process_create", "process_rollup", "process_launch") and proc_name and pid:
                node_id = make_process_id(host, proc_name, pid, timestamp)
                
                # Add process node
                G.add_node(
                    node_id,
                    type="process",
                    label=proc_name,
                    pid=pid,
                    commandline=ev.get("commandline") or "",
                    user=ev.get("user_name") or "",
                    timestamp=timestamp.isoformat() if isinstance(timestamp, datetime) else None,
                    file_hash=ev.get("file_hash_sha256") or "",
                    host=host
                )
                
                # Update the active process tracker
                active_processes[(host, pid)] = node_id

                # Link to parent process if exists
                parent_name = ev.get("parent_process_name")
                parent_pid = ev.get("parent_process_pid")
                
                if parent_name and parent_pid:
                    # Look up active parent
                    parent_node_id = active_processes.get((host, parent_pid))
                    
                    if not parent_node_id:
                        # Fallback: create placeholder parent process
                        parent_node_id = f"proc_{host}_{parent_name}_{parent_pid}_parent"
                        G.add_node(
                            parent_node_id,
                            type="process",
                            label=parent_name,
                            pid=parent_pid,
                            commandline="[Unobserved parent process]",
                            user="",
                            timestamp=None,
                            host=host
                        )
                    
                    # Add SPAWNED edge: parent -> child
                    G.add_edge(parent_node_id, node_id, relation="SPAWNED")

        # Step 2: Correlate network connections and file events to active processes
        for ev in sorted_events:
            ev_type = ev.get("event_type")
            host = ev.get("host_name") or "unknown_host"
            pid = ev.get("process_pid")
            timestamp = ev.get("timestamp")
            
            # Find closest matching active process node
            proc_node_id = active_processes.get((host, pid))
            if not proc_node_id:
                # If no active process matches the PID/host, create a generic process node
                proc_name = ev.get("process_name") or "unknown_process"
                if pid:
                    proc_node_id = f"proc_{host}_{proc_name}_{pid}_generic"
                    if not G.has_node(proc_node_id):
                        G.add_node(
                            proc_node_id,
                            type="process",
                            label=proc_name,
                            pid=pid,
                            commandline="",
                            user=ev.get("user_name") or "",
                            timestamp=None,
                            host=host
                        )
                else:
                    continue

            # Network events: Process -> IP
            if ev_type in ("network", "network_connect", "dns_query") or ev.get("dst_ip"):
                dst_ip = ev.get("dst_ip")
                dst_port = ev.get("dst_port")
                if dst_ip:
                    ip_node_id = f"ip_{dst_ip}"
                    if not G.has_node(ip_node_id):
                        G.add_node(
                            ip_node_id,
                            type="ip",
                            label=dst_ip,
                            port=dst_port,
                            details=f"Port: {dst_port}" if dst_port else ""
                        )
                    G.add_edge(proc_node_id, ip_node_id, relation="CONNECTED_TO")

            # File drops/creations: Process -> File
            elif ev_type in ("file", "file_create", "image_load") or ev.get("file_path"):
                file_path = ev.get("file_path")
                file_hash = ev.get("file_hash_sha256")
                
                if file_path:
                    # Normalize file name for label
                    file_name = file_path.split("\\")[-1].split("/")[-1]
                    file_node_id = f"file_{file_hash}" if file_hash else f"file_{file_path.replace(':', '_').replace('/', '_').replace('\\', '_')}"
                    
                    if not G.has_node(file_node_id):
                        G.add_node(
                            file_node_id,
                            type="file",
                            label=file_name,
                            path=file_path,
                            hash=file_hash or ""
                        )
                    G.add_edge(proc_node_id, file_node_id, relation="CREATED" if ev_type != "image_load" else "LOADED")

        # Step 3: Serialize to node-link format
        nodes_list = []
        for n_id, n_data in G.nodes(data=True):
            n_data["id"] = n_id
            nodes_list.append(n_data)

        edges_list = []
        for u, v, e_data in G.edges(data=True):
            edges_list.append({
                "source": u,
                "target": v,
                "relation": e_data.get("relation", "LINKED")
            })

        return {
            "nodes": nodes_list,
            "edges": edges_list
        }
