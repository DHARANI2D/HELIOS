from fastapi import APIRouter, BackgroundTasks, Depends, Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
import uuid
from datetime import datetime

from ...core.database import get_db
from ...core.models import Investigation, InvestigationStatusEnum, SeverityEnum
from ...core.config import settings
from .investigate import run_agent_triage_bg

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

@router.post("/alerts")
async def receive_webhook_alert(
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Receive alerts from Splunk, CrowdStrike, Wazuh, etc., and trigger agent investigation."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # 1. Parse alert structure dynamically based on recognizable fields
    title = "Webhook Alert"
    severity = SeverityEnum.info
    source_platform = "generic_webhook"
    alert_details = ""

    # CrowdStrike alert format recognition
    if "event" in payload and "DetectId" in payload.get("event", {}):
        event = payload["event"]
        title = f"CrowdStrike: {event.get('DetectName', 'Suspicious Activity')}"
        severity_val = str(event.get('SeverityName', 'medium')).lower()
        severity = SeverityEnum.critical if severity_val == "critical" else \
                   SeverityEnum.high if severity_val == "high" else \
                   SeverityEnum.medium if severity_val in ("medium", "medium_high") else \
                   SeverityEnum.low
        source_platform = "crowdstrike"
        alert_details = f"Host: {event.get('ComputerName')}, User: {event.get('UserName')}, CmdLine: {event.get('CommandLine')}"

    # Wazuh alert format recognition
    elif "rule" in payload and "id" in payload.get("rule", {}):
        rule = payload["rule"]
        title = f"Wazuh: {rule.get('description', 'Rule Triggered')}"
        level = int(rule.get('level', 1))
        severity = SeverityEnum.critical if level >= 12 else \
                   SeverityEnum.high if level >= 8 else \
                   SeverityEnum.medium if level >= 4 else \
                   SeverityEnum.low
        source_platform = "wazuh"
        alert_details = f"Agent: {payload.get('agent', {}).get('name')}, Details: {payload.get('full_log')}"

    # Splunk alerts format recognition
    elif "search_name" in payload or "result" in payload:
        title = f"Splunk Alert: {payload.get('search_name', 'Custom Query Triggered')}"
        severity = SeverityEnum.high
        source_platform = "splunk"
        result = payload.get("result", {})
        alert_details = f"Result details: {result}"

    # Google SecOps UDM alert format recognition
    elif "udm" in payload:
        udm = payload["udm"]
        title = f"SecOps Alert: {udm.get('metadata', {}).get('product_name', 'Rule Trigger')}"
        severity = SeverityEnum.high
        source_platform = "google_secops"
        alert_details = f"UDM Raw: {udm}"

    # Generic or custom payload
    else:
        title = payload.get("title", payload.get("name", "Generic Alert Influx"))
        sev_str = str(payload.get("severity", "info")).lower()
        severity = SeverityEnum.critical if "critical" in sev_str else \
                   SeverityEnum.high if "high" in sev_str else \
                   SeverityEnum.medium if "medium" in sev_str else \
                   SeverityEnum.low
        alert_details = str(payload)

    # 2. Insert new investigation record
    investigation_id = str(uuid.uuid4())
    investigation = Investigation(
        id=investigation_id,
        title=title,
        status=InvestigationStatusEnum.pending,
        severity=severity,
        source_platform=source_platform,
        attack_summary=f"Inbound alert ingested via webhook. Details: {alert_details}"
    )
    db.add(investigation)
    await db.commit()

    # 3. Schedule asynchronous multi-agent triage
    background_tasks.add_task(run_agent_triage_bg, investigation_id=investigation_id)

    return {
        "status": "alert_received_and_scheduled",
        "investigation_id": investigation_id,
        "title": title,
        "platform": source_platform,
        "severity": severity
    }
