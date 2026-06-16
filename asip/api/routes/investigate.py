from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional
import os
import shutil
import uuid
from datetime import datetime

from ...core.database import get_db
from ...core.models import Investigation, NormalizedEvent, InvestigationStatusEnum, SeverityEnum
from ...core.config import settings
from ...intake.gateway import IntakeGateway, PasswordRequiredError, InvalidPasswordError
from ...intake.normalizer import LogNormalizer

router = APIRouter(prefix="/investigations", tags=["investigations"])
gateway = IntakeGateway(work_dir=settings.EXTRACT_DIR)
normalizer = LogNormalizer()

async def run_pipeline_bg(
    investigation_id: str,
    file_path: str,
    password: Optional[str] = None
):
    """Background task to run recursive archive extraction and log normalization."""
    # We open a database session manually since this is running as a background task
    from ...core.database import AsyncSessionLocal
    
    async with AsyncSessionLocal() as db:
        try:
            # Update status to parsing
            result = await db.execute(select(Investigation).where(Investigation.id == investigation_id))
            investigation = result.scalar_one_or_none()
            if not investigation:
                return
                
            investigation.status = InvestigationStatusEnum.parsing
            await db.commit()

            # Process upload (extract files recursively)
            extracted_files = await gateway.process_upload(
                file_path=file_path,
                password=password,
                investigation_id=investigation_id
            )

            # Insert logs into database
            total_events = 0
            for f in extracted_files:
                events_parsed = await normalizer.normalize_and_save(
                    file_path=f.extracted_path,
                    file_type=f.file_type,
                    investigation_id=investigation_id,
                    db_session=db
                )
                total_events += events_parsed

            # Complete investigation
            investigation.status = InvestigationStatusEnum.completed
            investigation.completed_at = datetime.utcnow()
            investigation.attack_summary = f"Ingested {len(extracted_files)} files. Total normalized events: {total_events}."
            await db.commit()

        except PasswordRequiredError as e:
            # Bubble up password prompt state
            result = await db.execute(select(Investigation).where(Investigation.id == investigation_id))
            investigation = result.scalar_one_or_none()
            if investigation:
                investigation.status = InvestigationStatusEnum.awaiting_password
                investigation.password_required = e.archive_name
                # Store paths in state to resume later
                investigation.archive_paths = {
                    "file_path": file_path,
                }
                await db.commit()

        except InvalidPasswordError:
            result = await db.execute(select(Investigation).where(Investigation.id == investigation_id))
            investigation = result.scalar_one_or_none()
            if investigation:
                investigation.status = InvestigationStatusEnum.awaiting_password
                investigation.password_required = f"Incorrect password for {investigation.password_required or 'archive'}. Please retry."
                await db.commit()

        except Exception as e:
            result = await db.execute(select(Investigation).where(Investigation.id == investigation_id))
            investigation = result.scalar_one_or_none()
            if investigation:
                investigation.status = InvestigationStatusEnum.failed
                investigation.root_cause = f"Pipeline Error: {str(e)}"
                await db.commit()

@router.post("/upload")
async def upload_evidence(
    background_tasks: BackgroundTasks,
    file: Optional[UploadFile] = File(None),
    title: Optional[str] = Form(None),
    severity: SeverityEnum = Form(SeverityEnum.info),
    password: Optional[str] = Form(None),
    alert_details: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db)
):
    """Upload alert logs or zip archives, or paste alert details and initiate background workflows."""
    investigation_id = str(uuid.uuid4())
    
    file_path = None
    if file and file.filename:
        temp_dir = os.path.join(settings.UPLOAD_DIR, investigation_id)
        os.makedirs(temp_dir, exist_ok=True)
        file_path = os.path.join(temp_dir, file.filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

    # Resolve Title
    resolved_title = title
    if not resolved_title:
        if file and file.filename:
            resolved_title = f"Investigation - {file.filename}"
        else:
            resolved_title = f"Investigation - Alert Influx ({datetime.utcnow().strftime('%Y-%m-%d %H:%M')})"

    # Create investigation row
    investigation = Investigation(
        id=investigation_id,
        title=resolved_title,
        status=InvestigationStatusEnum.pending,
        severity=severity,
        alert_details=alert_details
    )
    db.add(investigation)
    await db.commit()
    await db.refresh(investigation)

    # Route background processes
    if file_path:
        background_tasks.add_task(
            run_pipeline_bg,
            investigation_id=investigation_id,
            file_path=file_path,
            password=password
        )
    else:
        # Directly mark ingestion parsing complete (no files to normalize) and trigger swarming agents
        investigation.status = InvestigationStatusEnum.completed
        investigation.attack_summary = "Pasted alert metadata successfully ingested. Swarm triage triggered."
        await db.commit()
        background_tasks.add_task(
            run_agent_triage_bg,
            investigation_id=investigation_id
        )

    return {
        "investigation_id": investigation_id,
        "title": investigation.title,
        "status": investigation.status,
        "severity": investigation.severity,
        "created_at": investigation.created_at
    }

@router.post("/{investigation_id}/password")
async def submit_password(
    investigation_id: str,
    password: str = Form(...),
    background_tasks: BackgroundTasks = None,
    db: AsyncSession = Depends(get_db)
):
    """Provide password for password-protected archive and resume ingestion."""
    result = await db.execute(select(Investigation).where(Investigation.id == investigation_id))
    investigation = result.scalar_one_or_none()
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if investigation.status != InvestigationStatusEnum.awaiting_password:
        raise HTTPException(status_code=400, detail=f"Investigation is not awaiting a password (status: {investigation.status})")

    archive_state = investigation.archive_paths
    if not archive_state or "file_path" not in archive_state:
        raise HTTPException(status_code=400, detail="Cannot resume investigation: missing raw file path state")

    # Update status to pending
    investigation.status = InvestigationStatusEnum.pending
    investigation.password_required = None
    await db.commit()

    # Restart pipeline
    background_tasks.add_task(
        run_pipeline_bg,
        investigation_id=investigation_id,
        file_path=archive_state["file_path"],
        password=password
    )

    return {"status": "resumed", "investigation_id": investigation_id}

@router.get("/")
async def list_investigations(db: AsyncSession = Depends(get_db)):
    """List all investigations."""
    result = await db.execute(select(Investigation).order_by(Investigation.created_at.desc()))
    investigations = result.scalars().all()
    
    response = []
    for inv in investigations:
        # Get count of parsed events
        count_res = await db.execute(
            select(func.count(NormalizedEvent.id)).where(NormalizedEvent.investigation_id == inv.id)
        )
        event_count = count_res.scalar() or 0
        
        response.append({
            "id": inv.id,
            "title": inv.title,
            "status": inv.status,
            "severity": inv.severity,
            "created_at": inv.created_at,
            "completed_at": inv.completed_at,
            "password_required": inv.password_required,
            "event_count": event_count
        })
    return response

@router.get("/{investigation_id}")
async def get_investigation(investigation_id: str, db: AsyncSession = Depends(get_db)):
    """Get detailed investigation status and event statistics."""
    result = await db.execute(select(Investigation).where(Investigation.id == investigation_id))
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    # Get count of parsed events by type
    count_res = await db.execute(
        select(NormalizedEvent.event_type, func.count(NormalizedEvent.id))
        .where(NormalizedEvent.investigation_id == investigation_id)
        .group_by(NormalizedEvent.event_type)
    )
    event_stats = {row[0]: row[1] for row in count_res.all()}

    # Get some sample events
    sample_res = await db.execute(
        select(NormalizedEvent)
        .where(NormalizedEvent.investigation_id == investigation_id)
        .order_by(NormalizedEvent.timestamp.asc())
        .limit(100)
    )
    samples = sample_res.scalars().all()

    return {
        "id": inv.id,
        "title": inv.title,
        "status": inv.status,
        "severity": inv.severity,
        "created_at": inv.created_at,
        "completed_at": inv.completed_at,
        "password_required": inv.password_required,
        "root_cause": inv.root_cause,
        "attack_summary": inv.attack_summary,
        "event_stats": event_stats,
        "sample_events": [
            {
                "id": ev.id,
                "timestamp": ev.timestamp,
                "event_type": ev.event_type,
                "process_name": ev.process_name,
                "commandline": ev.commandline,
                "host_name": ev.host_name,
                "dst_ip": ev.dst_ip,
                "dst_port": ev.dst_port,
                "file_hash_sha256": ev.file_hash_sha256
            }
            for ev in samples
        ]
    }

@router.get("/{investigation_id}/events")
async def get_investigation_events(
    investigation_id: str,
    query: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """Query logs associated with an investigation with filters and search query."""
    from sqlalchemy import or_
    
    stmt = select(NormalizedEvent).where(NormalizedEvent.investigation_id == investigation_id)
    if event_type:
        stmt = stmt.where(NormalizedEvent.event_type == event_type)
    
    if query:
        search_filter = f"%{query}%"
        stmt = stmt.where(
            or_(
                NormalizedEvent.process_name.ilike(search_filter),
                NormalizedEvent.commandline.ilike(search_filter),
                NormalizedEvent.file_hash_sha256.ilike(search_filter),
                NormalizedEvent.dst_ip.ilike(search_filter),
                NormalizedEvent.host_name.ilike(search_filter)
            )
        )
        
    stmt = stmt.order_by(NormalizedEvent.timestamp.asc()).limit(limit).offset(offset)
    result = await db.execute(stmt)
    events = result.scalars().all()
    return events

@router.get("/{investigation_id}/graph")
async def get_investigation_graph(
    investigation_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Generates a forensic correlation graph of process, network, and file events."""
    from ...graph.entity_graph import EntityGraphBuilder
    
    stmt = select(NormalizedEvent).where(NormalizedEvent.investigation_id == investigation_id)
    result = await db.execute(stmt)
    db_events = result.scalars().all()
    
    # Map database objects to dictionaries for the graph builder
    events = []
    for ev in db_events:
        events.append({
            "event_type": ev.event_type,
            "timestamp": ev.timestamp,
            "host_name": ev.host_name,
            "host_ip": ev.host_ip,
            "user_name": ev.user_name,
            "process_name": ev.process_name,
            "process_pid": ev.process_pid,
            "parent_process_name": ev.parent_process_name,
            "parent_process_pid": ev.parent_process_pid,
            "commandline": ev.commandline,
            "file_path": ev.file_path,
            "file_hash_sha256": ev.file_hash_sha256,
            "dst_ip": ev.dst_ip,
            "dst_port": ev.dst_port,
        })
        
    builder = EntityGraphBuilder()
    graph_data = builder.build_graph(events)
    return graph_data

async def run_agent_triage_bg(investigation_id: str):
    """Background runner for the multi-agent LangGraph workflow."""
    from ...core.database import AsyncSessionLocal
    from ...agents.orchestrator import investigation_graph
    from ...graph.entity_graph import EntityGraphBuilder
    
    async with AsyncSessionLocal() as db:
        try:
            # 1. Update status to running
            result = await db.execute(select(Investigation).where(Investigation.id == investigation_id))
            inv = result.scalar_one_or_none()
            if not inv:
                return
            inv.status = InvestigationStatusEnum.running
            await db.commit()

            # 2. Fetch UES logs
            stmt = select(NormalizedEvent).where(NormalizedEvent.investigation_id == investigation_id)
            log_res = await db.execute(stmt)
            db_logs = log_res.scalars().all()
            
            logs = []
            for ev in db_logs:
                logs.append({
                    "event_type": ev.event_type,
                    "timestamp": ev.timestamp,
                    "host_name": ev.host_name,
                    "host_ip": ev.host_ip,
                    "user_name": ev.user_name,
                    "process_name": ev.process_name,
                    "process_pid": ev.process_pid,
                    "parent_process_name": ev.parent_process_name,
                    "parent_process_pid": ev.parent_process_pid,
                    "commandline": ev.commandline,
                    "file_path": ev.file_path,
                    "file_hash_sha256": ev.file_hash_sha256,
                    "dst_ip": ev.dst_ip,
                    "dst_port": ev.dst_port,
                })

            # 3. Build graph
            builder = EntityGraphBuilder()
            graph_data = builder.build_graph(logs)

            # 4. Trigger LangGraph orchestrator flow
            details = inv.alert_details or f"Alert severity set to {inv.severity.value}. Investigation initiated with {len(logs)} log entries."
            inputs = {
                "investigation_id": investigation_id,
                "alert_title": inv.title,
                "alert_details": details,
                "triage_data": {},
                "graph_data": graph_data,
                "logs": logs,
                "rca_data": {},
                "qa_data": {},
                "final_report": "",
                "qa_iterations": 0
            }
            
            outputs = await investigation_graph.ainvoke(inputs)

            # 5. Save report outputs to investigation record
            result = await db.execute(select(Investigation).where(Investigation.id == investigation_id))
            inv = result.scalar_one_or_none()
            if inv:
                inv.status = InvestigationStatusEnum.completed
                inv.root_cause = outputs.get("rca_data", {}).get("root_cause", "RCA reasoning complete.")
                inv.attack_summary = outputs.get("final_report", "Report generated successfully.")
                inv.confidence_score = outputs.get("rca_data", {}).get("confidence_score", 0.9)
                inv.completed_at = datetime.utcnow()
                await db.commit()
                
                # 6. Index completed incident into semantic memory
                try:
                    from ...rag.incident_memory import IncidentMemoryManager
                    memory_mgr = IncidentMemoryManager()
                    await memory_mgr.index_incident(
                        investigation_id=investigation_id,
                        title=inv.title,
                        root_cause=inv.root_cause,
                        attack_summary=inv.attack_summary
                    )
                except Exception:
                    pass  # Graceful degradation if vector storage is offline

        except Exception as e:
            result = await db.execute(select(Investigation).where(Investigation.id == investigation_id))
            inv = result.scalar_one_or_none()
            if inv:
                inv.status = InvestigationStatusEnum.failed
                inv.attack_summary = f"Multi-Agent Execution Failed: {str(e)}"
                await db.commit()

@router.post("/{investigation_id}/triage")
async def trigger_agent_triage(
    investigation_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Trigger the multi-agent investigation and triage workflow in the background."""
    result = await db.execute(select(Investigation).where(Investigation.id == investigation_id))
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if inv.status in (InvestigationStatusEnum.running, InvestigationStatusEnum.parsing):
        raise HTTPException(status_code=400, detail=f"Triage is already running or parsing (status: {inv.status})")

    background_tasks.add_task(run_agent_triage_bg, investigation_id=investigation_id)
    return {"status": "initiated", "investigation_id": investigation_id}



