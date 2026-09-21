import json
from datetime import datetime
from typing import List, Dict, Any, Union

class GoogleSecOpsParser:
    # UDM Event Types mapped to UES event types
    UDM_TYPE_MAP = {
        "PROCESS_LAUNCH": "process",
        "PROCESS_TERMINATE": "process",
        "NETWORK_CONNECTION": "network",
        "NETWORK_HTTP": "network",
        "NETWORK_DNS": "dns",
        "FILE_CREATION": "file",
        "FILE_MODIFICATION": "file",
        "USER_LOGIN": "auth",
        "REGISTRY_MODIFICATION": "registry",
    }

    def parse(self, data: Union[str, List[Dict], Dict]) -> List[Dict[str, Any]]:
        """Parses Google SecOps UDM records."""
        events = []
        raw_records = []

        if isinstance(data, str):
            try:
                parsed = json.loads(data)
                if isinstance(parsed, list):
                    raw_records = parsed
                elif isinstance(parsed, dict):
                    # Check if it has an events field (common container)
                    if "events" in parsed and isinstance(parsed["events"], list):
                        raw_records = parsed["events"]
                    else:
                        raw_records = [parsed]
            except Exception:
                for line in data.strip().split("\n"):
                    if not line.strip():
                        continue
                    try:
                        raw_records.append(json.loads(line))
                    except Exception:
                        continue
        elif isinstance(data, list):
            raw_records = data
        elif isinstance(data, dict):
            raw_records = [data]

        for record in raw_records:
            try:
                parsed = self._parse_record(record)
                if parsed:
                    events.append(parsed)
            except Exception:
                continue

        return events

    def _parse_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        metadata = record.get("metadata", {})
        udm_type = metadata.get("event_type", "UNKNOWN")
        event_type = self.UDM_TYPE_MAP.get(udm_type, "unknown")

        # Timestamp
        ts_str = metadata.get("event_timestamp")
        timestamp = datetime.utcnow()
        if ts_str:
            try:
                timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                pass

        # Entities
        principal = record.get("principal", {})
        target = record.get("target", {})
        network = record.get("network", {})

        host_name = principal.get("hostname") or target.get("hostname") or ""
        host_ip = principal.get("ip", [""])[0] if isinstance(principal.get("ip"), list) and principal.get("ip") else principal.get("ip") or ""
        user_name = principal.get("user", {}).get("userid") or ""

        # Process info
        target_process = target.get("process", {})
        process_name = target_process.get("file", {}).get("name") or ""
        commandline = target_process.get("command_line") or ""
        process_pid = None
        if target_process.get("pid"):
            try:
                process_pid = int(target_process["pid"])
            except ValueError:
                pass

        # Parent process info
        parent_process = target_process.get("parent_process", {})
        parent_name = parent_process.get("file", {}).get("name") or ""
        parent_pid = None
        if parent_process.get("pid"):
            try:
                parent_pid = int(parent_process["pid"])
            except ValueError:
                pass

        # Network destination
        dst_ip = target.get("ip", [""])[0] if isinstance(target.get("ip"), list) and target.get("ip") else target.get("ip") or ""
        dst_port = None
        if target.get("port"):
            try:
                dst_port = int(target["port"])
            except ValueError:
                pass
        
        # File info
        file_path = target.get("file", {}).get("full_path") or ""
        file_hash = target.get("file", {}).get("sha256") or ""

        return {
            "timestamp": timestamp,
            "source_platform": "google_secops",
            "event_type": event_type,
            "host_name": host_name,
            "host_ip": host_ip,
            "user_name": user_name,
            "process_name": process_name,
            "process_pid": process_pid,
            "parent_process_name": parent_name,
            "parent_process_pid": parent_pid,
            "commandline": commandline,
            "file_path": file_path,
            "file_hash_sha256": file_hash,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "raw_event": record,
            "tags": ["google_secops", udm_type]
        }
