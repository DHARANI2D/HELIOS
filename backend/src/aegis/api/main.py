from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
from fastapi.middleware.cors import CORSMiddleware
import time
import random
from sqlmodel import Session, select, delete
from aegis.db import engine, init_db, Agent, AuditLog, GlobalStats

from aegis.identity.idp import TrustAuthority
from aegis.policy.engine import PolicyEvaluator
from aegis.audit.ledger import AuditLedger
from aegis.governance.trust import AdaptiveTrustEngine
from aegis.governance.isolation import ProgressiveIsolationEngine
from aegis.governance.constitution import AIConstitution

from aegis.config import settings
from aegis.logger import logger

app = FastAPI(title=settings.APP_NAME)

logger.info(f"Starting {settings.APP_NAME} in {settings.ENVIRONMENT} mode")

# Enable CORS for the React Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Core Engines
ta = TrustAuthority()
# Seed Realistic Fleet
pe = PolicyEvaluator("aegis/policy/intents.yaml")
ledger = AuditLedger()
trust_engine = AdaptiveTrustEngine()
isolation_manager = ProgressiveIsolationEngine()

@app.on_event("startup")
def on_startup():
    init_db()
    # Initialize Global Stats if not exists
    with Session(engine) as session:
        stats = session.get(GlobalStats, 1)
        if not stats:
            session.add(GlobalStats(id=1))
            session.commit()

@app.get("/agents")
def get_agents():
    with Session(engine) as session:
        agents = session.exec(select(Agent)).all()
        return [{
            "id": a.id,
            "trust": a.trust_score,
            "status": a.status,
            "level": a.level,
            "mode": a.mode
        } for a in agents]

@app.get("/stats")
def get_stats():
    with Session(engine) as session:
        agents = session.exec(select(Agent)).all()
        stats = session.get(GlobalStats, 1)
        
        avg_trust = sum(a.trust_score for a in agents) / len(agents) if agents else 100.0
        
        return {
            "active_nodes": len(agents),
            "avg_trust": f"{avg_trust:.1f}%",
            "interventions": stats.interventions if stats else 0,
            "pending": stats.pending_reviews if stats else 0
        }

@app.get("/logs")
def get_logs():
    return ledger.get_logs()[-10:] # Return last 10 for performance

@app.post("/penalty/{ai_id}")
def apply_penalty(ai_id: str, points: float):
    if ai_id not in ta.registry:
        raise HTTPException(status_code=404, detail="Agent not found")
    trust_engine.apply_penalty(ai_id, points)
    return {"status": "success", "new_trust": trust_engine.get_trust(ai_id)}

@app.post("/identity/issue")
def issue_id_query(ai_id: str) -> dict:
    """Issue a new identity via query parameter (legacy)."""
    identity = ta.issue_identity(ai_id)
    return {"status": "issued", "ai_id": ai_id}

@app.post("/identity/issue/{ai_id}")
def issue_id_path(ai_id: str) -> dict:
    """Issue a new identity via path parameter (preferred)."""
    identity = ta.issue_identity(ai_id)
    return {"status": "issued", "ai_id": ai_id}

@app.post("/governance/purge")
def global_purge():
    with Session(engine) as session:
        # Revoke all and set high isolation
        agents = session.exec(select(Agent)).all()
        for a in agents:
            a.status = "REVOKED"
            a.level = 0
            a.mode = "ISOLATED"
            session.add(a)
        session.commit()
    return {"status": "LOCKDOWN_ACTIVE"}

@app.post("/simulate/log")
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

@app.post("/simulator/reset")
def reset_db():
    with Session(engine) as session:
        session.exec(delete(Agent))
        session.exec(delete(AuditLog))
        session.commit()
    return {"status": "RESET_COMPLETE"}

@app.get("/health")
def health():
    return {"status": "OPERATIONAL", "safety_layer": "ACTIVE"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
