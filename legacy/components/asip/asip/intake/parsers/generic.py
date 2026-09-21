import json
import re
import pandas as pd
import io
from datetime import datetime
from typing import List, Dict, Any, Union

class GenericParser:
    # ISO-8601, RFC3339, Syslog-style date patterns
    TIMESTAMP_PATTERNS = [
        re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b'),
        re.compile(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b')
    ]

    # Common fields in general logs
    IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')

    def parse(self, content: Union[str, bytes], filename: str = "") -> List[Dict[str, Any]]:
        """Fallback parser for unstructured logs or generic formats."""
        events = []
        text_content = ""
        
        if isinstance(content, bytes):
            try:
                text_content = content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    text_content = content.decode('latin-1')
                except Exception:
                    return []
        else:
            text_content = content

        text_content = text_content.strip()
        if not text_content:
            return []

        # 1. Try parsing as JSON array or JSON lines
        if text_content.startswith("[") or text_content.startswith("{"):
            try:
                parsed = json.loads(text_content)
                if isinstance(parsed, list):
                    return self._normalize_json_list(parsed)
                elif isinstance(parsed, dict):
                    return self._normalize_json_list([parsed])
            except Exception:
                # Try JSON lines
                json_lines = []
                for line in text_content.split("\n"):
                    if not line.strip():
                        continue
                    try:
                        json_lines.append(json.loads(line))
                    except Exception:
                        pass
                if json_lines:
                    return self._normalize_json_list(json_lines)

        # 2. Try parsing as CSV if it has commas
        if "," in text_content.split("\n")[0] or "\t" in text_content.split("\n")[0]:
            try:
                sep = "\t" if "\t" in text_content.split("\n")[0] else ","
                df = pd.read_csv(io.StringIO(text_content), sep=sep)
                if len(df.columns) > 1:
                    # Treat it as a generic table
                    # Convert to list of dicts and parse
                    records = df.to_dict(orient="records")
                    return self._normalize_json_list(records)
            except Exception:
                pass

        # 3. Handle raw unstructured Syslog/plain text logs
        lines = text_content.split("\n")
        for line in lines:
            if not line.strip():
                continue
            event = self._parse_raw_line(line, filename)
            if event:
                events.append(event)

        return events

    def _normalize_json_list(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized = []
        for r in records:
            # Flatten dict slightly if needed, but do best-effort mapping
            timestamp = datetime.utcnow()
            for ts_field in ["timestamp", "time", "date", "@timestamp", "_time", "DateTime"]:
                if ts_field in r and r[ts_field]:
                    try:
                        timestamp = pd.to_datetime(str(r[ts_field])).to_pydatetime()
                        break
                    except Exception:
                        pass
            
            # Extract basic UES fields
            event = {
                "timestamp": timestamp,
                "source_platform": "generic",
                "event_type": str(r.get("event_type") or r.get("action") or r.get("category") or "log"),
                "host_name": str(r.get("host") or r.get("hostname") or r.get("computer") or ""),
                "host_ip": str(r.get("host_ip") or r.get("ip") or r.get("src_ip") or ""),
                "user_name": str(r.get("user") or r.get("username") or r.get("user_name") or ""),
                "process_name": str(r.get("process") or r.get("process_name") or r.get("exe") or ""),
                "process_pid": self._to_int(r.get("pid") or r.get("process_id")),
                "parent_process_name": str(r.get("parent_process") or r.get("parent_process_name") or ""),
                "parent_process_pid": self._to_int(r.get("parent_pid")),
                "commandline": str(r.get("commandline") or r.get("cmdline") or r.get("command") or ""),
                "file_path": str(r.get("file_path") or r.get("path") or ""),
                "file_hash_sha256": str(r.get("sha256") or r.get("file_hash") or ""),
                "dst_ip": str(r.get("dst_ip") or r.get("dest_ip") or r.get("destination") or ""),
                "dst_port": self._to_int(r.get("dst_port") or r.get("port")),
                "raw_event": r,
                "tags": ["generic"]
            }
            normalized.append(event)
        return normalized

    def _parse_raw_line(self, line: str, filename: str) -> Dict[str, Any]:
        # Parse timestamp from line
        timestamp = datetime.utcnow()
        for pattern in self.TIMESTAMP_PATTERNS:
            match = pattern.search(line)
            if match:
                try:
                    ts_str = match.group(0)
                    timestamp = pd.to_datetime(ts_str).to_pydatetime()
                    break
                except Exception:
                    pass

        # Extract IPs from line
        ips = self.IP_PATTERN.findall(line)
        host_ip = ips[0] if len(ips) > 0 else ""
        dst_ip = ips[1] if len(ips) > 1 else ""

        # Extract hashes
        hashes = self.SHA256_PATTERN.findall(line)
        sha256 = hashes[0] if hashes else ""

        return {
            "timestamp": timestamp,
            "source_platform": "generic_unstructured",
            "event_type": "log_line",
            "host_name": filename,
            "host_ip": host_ip,
            "user_name": "",
            "process_name": "",
            "process_pid": None,
            "parent_process_name": "",
            "parent_process_pid": None,
            "commandline": "",
            "file_path": "",
            "file_hash_sha256": sha256,
            "dst_ip": dst_ip,
            "dst_port": None,
            "raw_event": {"message": line},
            "tags": ["generic_text"]
        }

    def _to_int(self, val: Any) -> Optional[int]:
        if val is not None:
            try:
                return int(float(str(val)))
            except ValueError:
                pass
        return None
