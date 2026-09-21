import json
from datetime import datetime
from typing import List, Dict, Any, Union

class CrowdStrikeParser:
    EVENT_TYPE_MAP = {
        "ProcessRollup2": "process",
        "NetworkConnectIP4": "network",
        "DnsRequest": "dns",
        "FileOpenInfo": "file",
        "RegGenericValueUpdate": "registry",
        "UserLogon": "auth",
        "DetectionSummaryEvent": "alert"
    }

    def parse(self, data: Union[str, List[Dict], Dict]) -> List[Dict[str, Any]]:
        """Parses CrowdStrike logs and converts them to the universal schema format."""
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
                # Try reading line by line (JSON lines)
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
                parsed_event = self._parse_record(record)
                if parsed_event:
                    events.append(parsed_event)
            except Exception:
                continue

        return events

    def _parse_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        event_type_raw = record.get("EventType") or record.get("event_simpleName") or "unknown"
        event_type = self.EVENT_TYPE_MAP.get(event_type_raw, "unknown")

        timestamp_raw = (
            record.get("ProcessStartTime") or 
            record.get("timestamp") or 
            record.get("ContextTimeStamp") or
            record.get("UTCTimestamp")
        )
        timestamp = self._parse_timestamp(timestamp_raw)

        # Build Normalized event dict
        return {
            "timestamp": timestamp,
            "source_platform": "crowdstrike",
            "event_type": event_type,
            "host_name": record.get("ComputerName") or record.get("aid") or "",
            "host_ip": record.get("LocalAddressIP4") or record.get("LocalIP") or "",
            "user_name": record.get("UserName") or record.get("UserSid") or "",
            "process_name": record.get("FileName") or record.get("ImageFileName") or "",
            "process_pid": int(record["ProcessId"]) if record.get("ProcessId") else None,
            "parent_process_name": record.get("ParentBaseFileName") or record.get("ParentImageFileName") or "",
            "parent_process_pid": int(record["ParentProcessId"]) if record.get("ParentProcessId") else None,
            "commandline": record.get("CommandLine") or "",
            "file_path": record.get("FilePath") or record.get("TargetFilename") or "",
            "file_hash_sha256": record.get("SHA256HashData") or record.get("sha256") or "",
            "dst_ip": record.get("RemoteAddressIP4") or record.get("RemoteIP") or "",
            "dst_port": int(record["RemotePort"]) if record.get("RemotePort") else None,
            "raw_event": record,
            "tags": ["crowdstrike", event_type_raw]
        }

    def _parse_timestamp(self, raw: Any) -> datetime:
        if not raw:
            return datetime.utcnow()
        try:
            if isinstance(raw, (int, float)):
                # Handle epoch timestamp in seconds or milliseconds
                if raw > 1e12:
                    return datetime.fromtimestamp(raw / 1000.0)
                return datetime.fromtimestamp(raw)
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except Exception:
            return datetime.utcnow()
