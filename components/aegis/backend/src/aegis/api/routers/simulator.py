from fastapi import APIRouter
from typing import Dict, Any
from sqlmodel import Session
from aegis.db import engine, GlobalStats
from aegis.audit.ledger import AuditLedger
import time

router = APIRouter(prefix="/simulate", tags=["Simulator"])
ledger = AuditLedger()

@router.post("/log")
def submit_sim_log(log_data: Dict[str, Any]):
    """Simulator-only endpoint to populate logs for demonstration."""
    ai_id = log_data.get("ai_id", "UNKNOWN")
    intent = log_data.get("intent", "UNKNOWN")
    decision = log_data.get("decision", "ALLOW")
    reason = log_data.get("reason", "Simulated Event")
    
    # Update interventions counter if denied
    if decision == "DENY":
        with Session(engine) as session:
            stats = session.get(GlobalStats, 1)
            if stats:
                stats.interventions += 1
                session.add(stats)
                session.commit()

    # Mock signature for simulation
    signature = "SIMULATED_SIG_" + str(time.time())
    
    ledger.log_decision(ai_id, intent, decision, reason, signature)
    return {"status": "logged"}
