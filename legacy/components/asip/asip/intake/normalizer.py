import os
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import insert
from pathlib import Path

# Import database models
from ..core.models import NormalizedEvent, Investigation
from ..core.database import AsyncSessionLocal

# Import parsers
from .parsers.sysmon import SysmonParser
from .parsers.crowdstrike import CrowdStrikeParser
from .parsers.splunk import SplunkParser
from .parsers.wazuh import WazuhParser
from .parsers.google_secops import GoogleSecOpsParser
from .parsers.generic import GenericParser

class LogNormalizer:
    def __init__(self):
        self.sysmon_parser = SysmonParser()
        self.crowdstrike_parser = CrowdStrikeParser()
        self.splunk_parser = SplunkParser()
        self.wazuh_parser = WazuhParser()
        self.google_secops_parser = GoogleSecOpsParser()
        self.generic_parser = GenericParser()

    async def normalize_and_save(
        self,
        file_path: str,
        file_type: str,
        investigation_id: str,
        db_session: AsyncSession
    ) -> int:
        """
        Parses a file, converts events into the Universal Event Schema (UES), 
        and persists them into the database. Returns the number of events parsed.
        """
        if not os.path.exists(file_path):
            return 0

        # Read file contents
        content_bytes = b""
        content_str = ""
        
        # Read text or bytes based on file types
        if file_type not in ("evtx", "xlsx", "xls"):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content_str = f.read()
            except Exception:
                pass
        
        if not content_str:
            try:
                with open(file_path, "rb") as f:
                    content_bytes = f.read()
            except Exception:
                return 0

        parsed_events: List[Dict[str, Any]] = []
        filename = Path(file_path).name

        # Route to correct parser
        # Detect based on file type or content signature
        if file_type == "evtx":
            parsed_events = self.sysmon_parser.parse(file_path)
        elif file_type == "csv":
            # Check Splunk vs generic CSV
            data = content_bytes if content_bytes else content_str.encode('utf-8')
            parsed_events = self.splunk_parser.parse(data, file_type="csv")
            if not parsed_events:
                parsed_events = self.generic_parser.parse(data, filename=filename)
        elif file_type in ("xlsx", "xls"):
            data = content_bytes
            parsed_events = self.splunk_parser.parse(data, file_type=file_type)
        elif file_type == "json":
            # Read JSON and parse
            raw_str = content_str if content_str else content_bytes.decode('utf-8', errors='ignore')
            
            # Check if Wazuh, Crowdstrike, Google SecOps, or generic
            if "event_simpleName" in raw_str or "EventType" in raw_str:
                parsed_events = self.crowdstrike_parser.parse(raw_str)
            elif "rule" in raw_str and "level" in raw_str:
                parsed_events = self.wazuh_parser.parse(raw_str)
            elif "metadata" in raw_str and "event_type" in raw_str:
                parsed_events = self.google_secops_parser.parse(raw_str)
            else:
                # Fallback to general JSON parser
                parsed_events = self.generic_parser.parse(raw_str, filename=filename)
        else:
            # Fallback to generic parsing for plain text, log files, etc.
            data = content_str if content_str else content_bytes.decode('utf-8', errors='ignore')
            parsed_events = self.generic_parser.parse(data, filename=filename)

        if not parsed_events:
            return 0

        # Save to database in batches to optimize insertion speed
        batch_size = 500
        for i in range(0, len(parsed_events), batch_size):
            batch = parsed_events[i:i + batch_size]
            db_records = []
            for event in batch:
                event["investigation_id"] = investigation_id
                db_records.append(event)
            
            # Perform bulk insert
            await db_session.execute(insert(NormalizedEvent), db_records)
            await db_session.flush()

        return len(parsed_events)
