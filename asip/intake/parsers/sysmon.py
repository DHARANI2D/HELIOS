import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Any, Optional
import os

try:
    import Evtx.Evtx as evtx
    has_evtx = True
except ImportError:
    has_evtx = False

class SysmonParser:
    # Sysmon Event ID to human readable event types
    EVENT_ID_MAP = {
        1: "process_create",
        3: "network_connect",
        7: "image_load",
        8: "create_remote_thread",
        10: "process_access",
        11: "file_create",
        12: "registry_add_delete",
        13: "registry_set",
        15: "file_create_stream_hash",
        22: "dns_query",
        23: "file_delete",
    }
    
    def parse(self, evtx_path: str) -> List[Dict[str, Any]]:
        """Parses Windows EVTX records and returns normalized logs."""
        if not has_evtx:
            # Return empty or raise if python-evtx not available
            return []
            
        events = []
        if not os.path.exists(evtx_path):
            return []

        try:
            with evtx.Evtx(evtx_path) as log:
                for record in log.records():
                    try:
                        xml_str = record.xml()
                        event = self._parse_xml(xml_str)
                        if event:
                            events.append(event)
                    except Exception:
                        continue
        except Exception:
            pass

        return events

    def _parse_xml(self, xml_str: str) -> Optional[Dict[str, Any]]:
        try:
            # Parse XML event representation
            root = ET.fromstring(xml_str)
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
            
            system = root.find("e:System", ns)
            if system is None:
                return None
                
            event_id_el = system.find("e:EventID", ns)
            if event_id_el is None or not event_id_el.text:
                return None
                
            event_id = int(event_id_el.text)
            
            # Map event type
            event_type = self.EVENT_ID_MAP.get(event_id, f"windows_event_{event_id}")
            
            # Timestamp
            time_created = system.find("e:TimeCreated", ns)
            timestamp_str = time_created.get("SystemTime") if time_created is not None else None
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                except ValueError:
                    timestamp = datetime.utcnow()
            else:
                timestamp = datetime.utcnow()
                
            # Host name
            computer_el = system.find("e:Computer", ns)
            host_name = computer_el.text if computer_el is not None else ""

            # EventData fields extraction
            event_data = root.find("e:EventData", ns)
            data = {}
            if event_data is not None:
                for item in event_data.findall("e:Data", ns):
                    name = item.get("Name", "")
                    value = item.text or ""
                    data[name] = value

            # Extract fields for Universal Event Schema (UES)
            # Process Creation (Event ID 1)
            process_name = data.get("Image", "").split("\\")[-1] if "Image" in data else ""
            parent_name = data.get("ParentImage", "").split("\\")[-1] if "ParentImage" in data else ""
            
            # Fallbacks
            if not process_name and "ProcessName" in data:
                process_name = data["ProcessName"]
                
            # Network Connections (Event ID 3)
            dst_ip = data.get("DestinationIp", "")
            dst_port = int(data.get("DestinationPort", 0)) if "DestinationPort" in data and data["DestinationPort"].isdigit() else None
            
            # Registry Operations (Event ID 12/13)
            file_path = data.get("TargetFilename", "") or data.get("Image", "") or data.get("TargetObject", "")
            
            # Hash
            hashes_str = data.get("Hashes", "")
            file_hash = self._extract_sha256(hashes_str) if hashes_str else ""
            
            # User Name
            user_name = data.get("User", "")
            if not user_name and "TargetUserName" in data:
                user_name = data["TargetUserName"]
            if not user_name and "SubjectUserName" in data:
                user_name = data["SubjectUserName"]

            return {
                "timestamp": timestamp,
                "source_platform": "sysmon",
                "event_type": event_type,
                "host_name": host_name,
                "host_ip": data.get("SourceIp", ""),
                "user_name": user_name,
                "process_name": process_name,
                "process_pid": int(data.get("ProcessId", 0)) if "ProcessId" in data and data["ProcessId"].isdigit() else None,
                "parent_process_name": parent_name,
                "parent_process_pid": int(data.get("ParentProcessId", 0)) if "ParentProcessId" in data and data["ParentProcessId"].isdigit() else None,
                "commandline": data.get("CommandLine", ""),
                "file_path": file_path,
                "file_hash_sha256": file_hash,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "raw_event": data,
                "tags": ["sysmon", f"event_id_{event_id}"]
            }
        except Exception:
            return None

    def _extract_sha256(self, hashes_str: str) -> str:
        for part in hashes_str.split(","):
            if "SHA256=" in part:
                return part.split("=")[1].strip()
        return ""
