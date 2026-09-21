import pandas as pd
import io
from datetime import datetime
from typing import List, Dict, Any, Union

class SplunkParser:
    # Typical field mappings from Splunk queries/exports to UES
    FIELD_MAPS = {
        "host_name": ["host", "ComputerName", "dest", "destination", "device_name", "dvc_name", "Computer"],
        "host_ip": ["dest_ip", "host_ip", "ip", "src_ip", "src", "clientip", "dvc_ip"],
        "user_name": ["user", "UserName", "src_user", "uid", "suser", "duser"],
        "process_name": ["process", "process_name", "Image", "FileName", "app", "exe"],
        "process_pid": ["pid", "process_id", "ProcessId"],
        "parent_process_name": ["parent_process", "parent_process_name", "ParentImage", "ParentBaseFileName"],
        "parent_process_pid": ["parent_pid", "parent_process_id", "ParentProcessId"],
        "commandline": ["commandline", "CommandLine", "cmdline", "process_exec", "arguments"],
        "file_path": ["file_path", "filePath", "TargetFilename", "file_name", "object"],
        "file_hash_sha256": ["sha256", "file_hash", "hash", "SHA256HashData", "hash_sha256"],
        "dst_ip": ["dest_ip", "destination_ip", "dst", "RemoteAddressIP4", "RemoteIP"],
        "dst_port": ["dest_port", "destination_port", "RemotePort", "port"],
        "event_type": ["event_type", "type", "action", "signature", "category"]
    }

    def parse(self, file_path_or_bytes: Union[str, bytes], file_type: str = "csv") -> List[Dict[str, Any]]:
        """Parses CSV or XLSX tables and normalizes them into Universal Event Schema dicts."""
        events = []
        try:
            if file_type == "csv":
                if isinstance(file_path_or_bytes, bytes):
                    df = pd.read_csv(io.BytesIO(file_path_or_bytes))
                else:
                    df = pd.read_csv(file_path_or_bytes)
            elif file_type == "xlsx" or file_type == "xls":
                if isinstance(file_path_or_bytes, bytes):
                    df = pd.read_excel(io.BytesIO(file_path_or_bytes))
                else:
                    df = pd.read_excel(file_path_or_bytes)
            else:
                return []
        except Exception:
            return []

        # Find match fields
        columns = list(df.columns)
        mapping = self._find_column_mapping(columns)

        for _, row in df.iterrows():
            try:
                row_dict = row.to_dict()
                
                # Check for timestamp
                timestamp = self._extract_timestamp(row_dict, columns)
                
                event = {
                    "timestamp": timestamp,
                    "source_platform": "splunk",
                    "event_type": self._get_mapped_value(row_dict, mapping, "event_type") or "generic_log",
                    "host_name": self._get_mapped_value(row_dict, mapping, "host_name") or "",
                    "host_ip": self._get_mapped_value(row_dict, mapping, "host_ip") or "",
                    "user_name": self._get_mapped_value(row_dict, mapping, "user_name") or "",
                    "process_name": self._get_mapped_value(row_dict, mapping, "process_name") or "",
                    "process_pid": self._get_int_value(row_dict, mapping, "process_pid"),
                    "parent_process_name": self._get_mapped_value(row_dict, mapping, "parent_process_name") or "",
                    "parent_process_pid": self._get_int_value(row_dict, mapping, "parent_process_pid"),
                    "commandline": self._get_mapped_value(row_dict, mapping, "commandline") or "",
                    "file_path": self._get_mapped_value(row_dict, mapping, "file_path") or "",
                    "file_hash_sha256": self._get_mapped_value(row_dict, mapping, "file_hash_sha256") or "",
                    "dst_ip": self._get_mapped_value(row_dict, mapping, "dst_ip") or "",
                    "dst_port": self._get_int_value(row_dict, mapping, "dst_port"),
                    "raw_event": row_dict,
                    "tags": ["splunk"]
                }
                events.append(event)
            except Exception:
                continue

        return events

    def _find_column_mapping(self, columns: List[str]) -> Dict[str, str]:
        mapping = {}
        for schema_field, splunk_options in self.FIELD_MAPS.items():
            for option in splunk_options:
                # Case-insensitive matching
                matched = next((col for col in columns if col.lower() == option.lower()), None)
                if matched:
                    mapping[schema_field] = matched
                    break
        return mapping

    def _get_mapped_value(self, row: Dict[str, Any], mapping: Dict[str, str], schema_field: str) -> Optional[str]:
        col_name = mapping.get(schema_field)
        if col_name and pd.notna(row.get(col_name)):
            return str(row[col_name]).strip()
        return None

    def _get_int_value(self, row: Dict[str, Any], mapping: Dict[str, str], schema_field: str) -> Optional[int]:
        val = self._get_mapped_value(row, mapping, schema_field)
        if val:
            try:
                # Handle floats represented as strings like "4512.0"
                return int(float(val))
            except ValueError:
                pass
        return None

    def _extract_timestamp(self, row: Dict[str, Any], columns: List[str]) -> datetime:
        # Check standard timestamp fields
        ts_options = ["_time", "time", "timestamp", "date", "created_at", "DateTime"]
        for opt in ts_options:
            col = next((c for c in columns if c.lower() == opt.lower()), None)
            if col and pd.notna(row.get(col)):
                try:
                    val = str(row[col])
                    # Try common conversions
                    if val.isdigit() or (val.replace('.', '', 1).isdigit() and '.' in val):
                        return datetime.fromtimestamp(float(val))
                    return pd.to_datetime(val).to_pydatetime()
                except Exception:
                    pass
        return datetime.utcnow()
