from fastapi import APIRouter, HTTPException
from sqlmodel import Session, select
from aegis.db import engine, Agent, BreachInvestigation
from typing import Dict, Any
import json
import time

router = APIRouter(tags=["Investigation"])

@router.get("/agents/{agent_id}/investigation")
def get_investigation(agent_id: str):
    """Get detailed breach investigation for a revoked agent"""
    with Session(engine) as session:
        # Get agent
        agent = session.get(Agent, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Get investigation
        investigation = session.exec(
            select(BreachInvestigation).where(BreachInvestigation.agent_id == agent_id)
        ).first()
        
        if not investigation:
            raise HTTPException(status_code=404, detail="No investigation found for this agent")
        
        # Parse evidence JSON
        evidence = json.loads(investigation.evidence) if investigation.evidence else {}
        
        return {
            "agent_id": agent_id,
            "agent_status": agent.status,
            "trust": agent.trust,
            "breach_type": investigation.breach_type,
            "severity": investigation.severity,
            "detection_mechanism": investigation.detection_mechanism,
            "evidence": evidence,
            "timestamp": investigation.timestamp,
            "revoked_at": investigation.revoked_at,
            "status": investigation.status,
            "recommendation": get_recommendation(investigation)
        }

@router.post("/agents/{agent_id}/restore")
def restore_agent(agent_id: str, justification: str = ""):
    """Restore a revoked agent after investigation"""
    with Session(engine) as session:
        # Get agent
        agent = session.get(Agent, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        if agent.status != "REVOKED":
            raise HTTPException(status_code=400, detail="Agent is not revoked")
        
        # Update agent
        agent.status = "Active"
        agent.trust = 100.0
        agent.level = 10
        agent.mode = "FULL_ACCESS"
        session.add(agent)
        
        # Update investigation
        investigation = session.exec(
            select(BreachInvestigation).where(BreachInvestigation.agent_id == agent_id)
        ).first()
        
        if investigation:
            investigation.status = "RESTORED"
            session.add(investigation)
        
        session.commit()
        
        return {
            "status": "success",
            "message": f"Agent {agent_id} restored",
            "justification": justification
        }

@router.post("/agents/{agent_id}/confirm-breach")
def confirm_breach(agent_id: str, notes: str = ""):
    """Confirm a breach investigation and permanently revoke agent"""
    with Session(engine) as session:
        investigation = session.exec(
            select(BreachInvestigation).where(BreachInvestigation.agent_id == agent_id)
        ).first()
        
        if not investigation:
            raise HTTPException(status_code=404, detail="No investigation found")
        
        investigation.status = "CONFIRMED"
        session.add(investigation)
        session.commit()
        
        return {
            "status": "success",
            "message": f"Breach confirmed for {agent_id}",
            "notes": notes
        }

def get_recommendation(investigation: BreachInvestigation) -> str:
    """Get recommended action based on investigation"""
    if investigation.severity == "CRITICAL":
        return "RECOMMENDED: Keep revoked. Issue new identity with stricter policies."
    elif investigation.severity == "HIGH":
        return "RECOMMENDED: Investigate thoroughly before restoring. Update security policies."
    else:
        return "RECOMMENDED: Review evidence. May be false positive - consider restoration."
