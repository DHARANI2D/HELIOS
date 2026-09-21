from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from ...core.config import settings
from ...core.database import get_db
from ...core.models import (
    Investigation, NormalizedEvent, IOC, MITREMapping, 
    TimelineEntry, InvestigationStatusEnum, SeverityEnum
)
from datetime import datetime, timedelta
import uuid

router = APIRouter(prefix="/settings", tags=["settings"])

class SettingsUpdateSchema(BaseModel):
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    
    OLLAMA_BASE_URL: Optional[str] = None
    LOCAL_MODEL: Optional[str] = None
    CLOUD_MODEL: Optional[str] = None
    
    EMBEDDING_PROVIDER: Optional[str] = None
    EMBEDDING_MODEL: Optional[str] = None

@router.get("")
async def get_settings():
    """Retrieve current active server settings (with masked credentials)."""
    def mask_key(k: Optional[str]) -> str:
        if not k:
            return ""
        return k[:8] + "..." if len(k) > 8 else "..."

    return {
        "OPENAI_API_KEY": mask_key(settings.OPENAI_API_KEY),
        "ANTHROPIC_API_KEY": mask_key(settings.ANTHROPIC_API_KEY),
        "VIRUSTOTAL_API_KEY": mask_key(settings.VIRUSTOTAL_API_KEY),
        "ABUSEIPDB_API_KEY": mask_key(settings.ABUSEIPDB_API_KEY),
        "OLLAMA_BASE_URL": settings.OLLAMA_BASE_URL,
        "LOCAL_MODEL": settings.LOCAL_MODEL,
        "CLOUD_MODEL": settings.CLOUD_MODEL,
        "EMBEDDING_PROVIDER": settings.EMBEDDING_PROVIDER,
        "EMBEDDING_MODEL": settings.EMBEDDING_MODEL
    }

@router.post("")
async def update_settings(payload: SettingsUpdateSchema):
    """Dynamically updates active configurations in-memory on the backend."""
    if payload.OPENAI_API_KEY is not None and not payload.OPENAI_API_KEY.endswith("..."):
        settings.OPENAI_API_KEY = payload.OPENAI_API_KEY or None
        
    if payload.ANTHROPIC_API_KEY is not None and not payload.ANTHROPIC_API_KEY.endswith("..."):
        settings.ANTHROPIC_API_KEY = payload.ANTHROPIC_API_KEY or None
        
    if payload.VIRUSTOTAL_API_KEY is not None and not payload.VIRUSTOTAL_API_KEY.endswith("..."):
        settings.VIRUSTOTAL_API_KEY = payload.VIRUSTOTAL_API_KEY or None
        
    if payload.ABUSEIPDB_API_KEY is not None and not payload.ABUSEIPDB_API_KEY.endswith("..."):
        settings.ABUSEIPDB_API_KEY = payload.ABUSEIPDB_API_KEY or None

    if payload.OLLAMA_BASE_URL is not None:
        settings.OLLAMA_BASE_URL = payload.OLLAMA_BASE_URL
        
    if payload.LOCAL_MODEL is not None:
        settings.LOCAL_MODEL = payload.LOCAL_MODEL
        
    if payload.CLOUD_MODEL is not None:
        settings.CLOUD_MODEL = payload.CLOUD_MODEL
        
    if payload.EMBEDDING_PROVIDER is not None:
        settings.EMBEDDING_PROVIDER = payload.EMBEDDING_PROVIDER
        
    if payload.EMBEDDING_MODEL is not None:
        settings.EMBEDDING_MODEL = payload.EMBEDDING_MODEL

    return {
        "status": "success",
        "message": "Configuration updated successfully in memory"
    }

@router.post("/demo")
async def trigger_demo_investigation(db: AsyncSession = Depends(get_db)):
    """Pre-populates a complete, simulated high-severity investigation in the DB for one-click demo purposes."""
    demo_id = str(uuid.uuid4())
    now = datetime.utcnow()
    
    # 1. Create completed Investigation
    investigation = Investigation(
        id=demo_id,
        title="[DEMO] Splunk: Suspicious Process Spawns from Office Application",
        status=InvestigationStatusEnum.completed,
        severity=SeverityEnum.high,
        created_at=now - timedelta(minutes=15),
        completed_at=now,
        alert_details="Alert Name: Office Document Spawns Command Interpreter\nParent Image: C:\\Program Files\\Microsoft Office\\root\\Office16\\winword.exe\nSpawned Image: C:\\Windows\\System32\\cmd.exe\nHost Name: server01.corp.internal\nUser Domain: CORP, Username: john.doe",
        root_cause="The incident was initiated when user john.doe opened the phishing attachment 'invoice.docx' via Outlook. VBA macros immediately triggered cmd.exe which spawned powershell.exe executing an encoded base64 connection string to a remote command & control Tor node.",
        confidence_score=0.98,
        attack_summary="""# INCIDENT INVESTIGATION REPORT: SPLUNK ALERT 2471

## 📌 Executive Summary
On **server01**, a **high-severity execution threat** was successfully triaged. The threat originated from a phishing email delivery leading to VBA macro execution within Microsoft Word. Immediate host isolation was executed.

## 🔍 Root Cause Analysis & Timeline
1. **Initial Access**: Outlook received mail containing attachment `invoice.docx`, opened by user `john.doe`.
2. **Execution**: Word macros executed `cmd.exe` which spawned `powershell.exe` containing an encoded base64 cradle.
3. **C2 beacon**: PowerShell established outbound TCP socket stream connection to `185.220.101.5:4444`.
4. **Persistence**: The threat dropped a secondary updates agent (`update.exe`) and set local Run persistence key.

## 🛡️ Response Playbook (Immediate Containment)
*   **Asset Isolation**: Isolate asset `server01` using EDR containment hooks.
*   **Credential Revocation**: Disable Active Directory sessions for `john.doe`.
*   **Proxy Block**: Add firewall block rules for Tor node IP `185.220.101.5` on proxy layers.
*   **Threat Hunt**: Sweep all hosts for dropper payload hash `a1b2c3d4e5f60718293a4...`

## ⚙️ Evidence Verification Notes (QA Swarm Approved)
✓ PowerShell execution logs verified (Sysmon Event ID 1)
✓ C2 outbound socket verified (Sysmon Event ID 3)
✓ Registry persistence entry validated (Sysmon Event ID 12)"""
    )
    db.add(investigation)
    await db.commit()

    # 2. Add Normalized UES Events
    event1 = NormalizedEvent(
        investigation_id=demo_id,
        timestamp=now - timedelta(minutes=14),
        source_platform="sysmon",
        event_type="process",
        host_name="server01",
        host_ip="10.0.0.5",
        user_name="john.doe",
        process_name="winword.exe",
        process_pid=3201,
        parent_process_name="outlook.exe",
        parent_process_pid=1202,
        commandline="C:\\Program Files\\Microsoft Office\\root\\Office16\\winword.exe /n C:\\Users\\john.doe\\Downloads\\invoice.docx"
    )
    event2 = NormalizedEvent(
        investigation_id=demo_id,
        timestamp=now - timedelta(minutes=13, seconds=30),
        source_platform="sysmon",
        event_type="process",
        host_name="server01",
        host_ip="10.0.0.5",
        user_name="john.doe",
        process_name="powershell.exe",
        process_pid=4512,
        parent_process_name="winword.exe",
        parent_process_pid=3201,
        commandline="powershell.exe -enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp..."
    )
    event3 = NormalizedEvent(
        investigation_id=demo_id,
        timestamp=now - timedelta(minutes=13, seconds=25),
        source_platform="sysmon",
        event_type="network",
        host_name="server01",
        host_ip="10.0.0.5",
        user_name="john.doe",
        process_name="powershell.exe",
        process_pid=4512,
        dst_ip="185.220.101.5",
        dst_port=4444
    )
    event4 = NormalizedEvent(
        investigation_id=demo_id,
        timestamp=now - timedelta(minutes=12),
        source_platform="sysmon",
        event_type="file",
        host_name="server01",
        host_ip="10.0.0.5",
        user_name="john.doe",
        process_name="powershell.exe",
        process_pid=4512,
        file_path="C:\\Users\\john\\AppData\\Roaming\\update.exe",
        file_hash_sha256="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
    )
    event5 = NormalizedEvent(
        investigation_id=demo_id,
        timestamp=now - timedelta(minutes=11, seconds=30),
        source_platform="sysmon",
        event_type="process",
        host_name="server01",
        host_ip="10.0.0.5",
        user_name="john.doe",
        process_name="update.exe",
        process_pid=7821,
        parent_process_name="powershell.exe",
        parent_process_pid=4512,
        commandline="C:\\Users\\john\\AppData\\Roaming\\update.exe",
        file_hash_sha256="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
    )
    db.add_all([event1, event2, event3, event4, event5])
    await db.commit()

    # 3. Add IOC Records
    ioc1 = IOC(
        investigation_id=demo_id,
        ioc_type="ipv4",
        value="185.220.101.5",
        confidence=0.99,
        context="TCP socket C2 connection opened by powershell.exe",
        vt_score="14/70",
        vt_malicious_count=14,
        abuseipdb_score=85,
        threat_actor="Malicious Command & Control Server",
        malware_family="AsyncRAT C2 Infrastructure"
    )
    ioc2 = IOC(
        investigation_id=demo_id,
        ioc_type="sha256",
        value="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        confidence=0.95,
        context="Secondary executable dropped in local AppData folder",
        vt_score="28/70",
        vt_malicious_count=28,
        malware_family="AsyncRAT Dropper Agent"
    )
    db.add_all([ioc1, ioc2])
    await db.commit()

    # 4. Add MITRE ATT&CK Mappings
    map1 = MITREMapping(
        investigation_id=demo_id,
        technique_id="T1566.001",
        technique_name="Spearphishing Attachment",
        tactic="Initial Access",
        evidence="winword.exe opened local payload attachment 'invoice.docx'",
        confidence=0.95
    )
    map2 = MITREMapping(
        investigation_id=demo_id,
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        evidence="winword.exe spawned powershell.exe executing base64 shell command",
        confidence=0.99
    )
    map3 = MITREMapping(
        investigation_id=demo_id,
        technique_id="T1071.001",
        technique_name="Web Protocols",
        tactic="Command and Control",
        evidence="powershell.exe established TCP connection to port 4444 on IP 185.220.101.5",
        confidence=0.97
    )
    db.add_all([map1, map2, map3])
    await db.commit()

    # 5. Add Timeline Entries
    t1 = TimelineEntry(
        investigation_id=demo_id,
        timestamp=now - timedelta(minutes=14),
        event_description="User opened invoice.docx macro attachment inside Word (outlook.exe -> winword.exe)",
        event_type="process",
        severity="low",
        evidence_source="Sysmon Event ID 1"
    )
    t2 = TimelineEntry(
        investigation_id=demo_id,
        timestamp=now - timedelta(minutes=13, seconds=30),
        event_description="Word macro executed cmd.exe which spawned powershell.exe with base64 download cradle",
        event_type="process",
        severity="high",
        evidence_source="Sysmon Event ID 1"
    )
    t3 = TimelineEntry(
        investigation_id=demo_id,
        timestamp=now - timedelta(minutes=13, seconds=25),
        event_description="powershell.exe established C2 socket connection to remote node 185.220.101.5:4444",
        event_type="network",
        severity="critical",
        evidence_source="Sysmon Event ID 3"
    )
    t4 = TimelineEntry(
        investigation_id=demo_id,
        timestamp=now - timedelta(minutes=12),
        event_description="update.exe payload dropped in local AppData Roaming folder by powershell.exe",
        event_type="file",
        severity="high",
        evidence_source="Sysmon Event ID 11"
    )
    t5 = TimelineEntry(
        investigation_id=demo_id,
        timestamp=now - timedelta(minutes=11, seconds=30),
        event_description="update.exe executed (PID 7821) as secondary threat runner",
        event_type="process",
        severity="critical",
        evidence_source="Sysmon Event ID 1"
    )
    db.add_all([t1, t2, t3, t4, t5])
    await db.commit()

    # 6. Index completed incident into semantic RAG memory
    try:
        from ...rag.incident_memory import IncidentMemoryManager
        memory_mgr = IncidentMemoryManager()
        await memory_mgr.index_incident(
            investigation_id=demo_id,
            title=investigation.title,
            root_cause=investigation.root_cause,
            attack_summary=investigation.attack_summary
        )
    except Exception:
        pass

    return {
        "status": "success",
        "message": "Complete offline demo investigation instantiated",
        "investigation_id": demo_id
    }
