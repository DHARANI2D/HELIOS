import json
from datetime import datetime
from typing import List, Dict, Any, Union

class WazuhParser:
    def parse(self, data: Union[str, List[Dict], Dict]) -> List[Dict[str, Any]]:
        """Parses Wazuh JSON alerts and normalizes them."""
        events = []
        raw_records = []

        if isinstance(data, str):
            try:
                parsed = json.loads(data)
                if isinstance(parsed, list):
                    raw_records = parsed
                elif isinstance(parsed, dict):
                    raw_records = [parsed]
            except Exception:
                # Try JSON Lines
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
        # Extract rule metadata
        rule = record.get("rule", {})
        rule_id = rule.get("id", "unknown")
        rule_desc = rule.get("description", "")
        level = rule.get("level", 0)

        # Event type mapping based on rule description or ID
        event_type = "alert"
        if "syscheck" in record:
            event_type = "file"
        elif "netinfo" in record or "port" in record:
            event_type = "network"

        # Timestamp
        timestamp_str = record.get("timestamp") or record.get("@timestamp")
        timestamp = datetime.utcnow()
        if timestamp_str:
            try:
                # Format: 2024-06-15T08:01:23.123+0000
                cleaned_ts = str(timestamp_str).replace("Z", "+00:00")
                timestamp = datetime.fromisoformat(cleaned_ts)
            except Exception:
                pass

        # Agent metadata
        agent = record.get("agent", {})
        host_name = agent.get("name") or record.get("hostname") or ""
        host_ip = agent.get("ip") or ""

        # Syscheck (integrity monitoring)
        syscheck = record.get("syscheck", {})
        file_path = syscheck.get("path") or ""
        file_hash = syscheck.get("sha256_after") or syscheck.get("md5_after") or ""

        # Data block
        data = record.get("data", {})
        user_name = data.get("dstuser") or data.get("srcuser") or record.get("decoder", {}).get("name") or ""
        
        process_name = data.get("process", {}).get("name") or data.get("program_name") or ""
        process_pid = None
        if data.get("process", {}).get("pid"):
            try:
                process_pid = int(data["process"]["pid"])
            except ValueError:
                pass

        # Network details
        dst_ip = data.get("dstip") or data.get("srcip") or ""
        dst_port = None
        if data.get("dstport"):
            try:
                dst_port = int(data["dstport"])
            except ValueError:
                pass

        return {
            "timestamp": timestamp,
            "source_platform": "wazuh",
            "event_type": event_type,
            "host_name": host_name,
            "host_ip": host_ip,
            "user_name": user_name,
            "process_name": process_name,
            "process_pid": process_pid,
            "parent_process_name": "",
            "parent_process_pid": None,
            "commandline": data.get("command") or data.get("system_name") or "",
            "file_path": file_path,
            "file_hash_sha256": file_hash if len(file_hash) == 64 else "",
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "raw_event": record,
            "tags": ["wazuh", f"rule_{rule_id}", f"level_{level}"]
        }
