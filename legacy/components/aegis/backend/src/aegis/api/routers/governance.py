from fastapi import APIRouter, HTTPException
from sqlmodel import Session, select, delete
from aegis.db import engine, Agent, GlobalStats, AuditLog
from aegis.governance.trust import AdaptiveTrustEngine
from typing import Dict, Any
import time

router = APIRouter(tags=["Governance"])
trust_engine = AdaptiveTrustEngine()

@router.post("/penalty/{ai_id}")
def apply_penalty(ai_id: str, points: float):
    # Check if agent exists in DB
    with Session(engine) as session:
        agent = session.get(Agent, ai_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
            
    trust_engine.apply_penalty(ai_id, points)
    return {"status": "success", "new_trust": trust_engine.get_trust(ai_id)}

@router.post("/governance/purge")
def global_purge():
    from aegis.db import BreachInvestigation
    import json
    
    with Session(engine) as session:
        # Revoke all and set high isolation
        agents = session.exec(select(Agent)).all()
        for a in agents:
            # Create breach investigation for each agent
            investigation = BreachInvestigation(
                agent_id=a.id,
                breach_type="GLOBAL_SECURITY_INCIDENT",
                severity="CRITICAL",
                detection_mechanism="Global Purge Triggered - System-wide security event detected",
                evidence=json.dumps({
                    "trigger": "Manual global purge execution",
                    "reason": "Emergency lockdown initiated by security team",
                    "previous_trust": a.trust,
                    "previous_status": a.status,
                    "previous_level": a.level,
                    "detection_methods": [
                        "Manual intervention",
                        "System-wide threat assessment"
                    ],
                    "timeline": [
                        {
                            "event": "Global purge initiated",
                            "timestamp": time.time()
                        }
                    ]
                })
            )
            session.add(investigation)
            
            # Revoke agent
            a.status = "REVOKED"
            a.level = 0
            a.mode = "ISOLATED"
            a.trust = 0.0
            session.add(a)
        
        session.commit()
    return {"status": "LOCKDOWN_ACTIVE", "agents_revoked": len(agents)}

@router.post("/simulator/reset")
def reset_db():
    with Session(engine) as session:
        session.exec(delete(Agent))
        session.exec(delete(AuditLog))
        # Reset global stats
        stats = session.get(GlobalStats, 1)
        if stats:
            stats.interventions = 0
            stats.pending_reviews = 0
            session.add(stats)
        session.commit()
    return {"status": "RESET_COMPLETE"}
