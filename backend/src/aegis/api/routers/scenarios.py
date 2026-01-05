from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from aegis.simulator.scenarios import SecurityScenarios
from aegis.identity.idp import TrustAuthority
from aegis.policy.engine import PolicyEvaluator
from aegis.audit.ledger import AuditLedger
from aegis.sidecar.proxy import AISidecar
from aegis.db import GlobalStats, engine
from sqlmodel import Session, select

router = APIRouter()

# Initialize core engines
ta = TrustAuthority()
pe = PolicyEvaluator("aegis/policy/intents.yaml")
ledger = AuditLedger()

@router.get("/scenarios")
def list_scenarios():
    """List all available security scenarios."""
    scenarios = SecurityScenarios.get_all_scenarios()
    return {
        "scenarios": [
            {
                "id": i,
                "name": s["name"],
                "description": s["description"],
                "severity": s["severity"]
            }
            for i, s in enumerate(scenarios)
        ]
    }

@router.post("/scenarios/run/{scenario_name}")
def run_scenario(scenario_name: str) -> Dict[str, Any]:
    """
    Execute a specific security scenario and return results.
    """
    scenario = SecurityScenarios.get_scenario_by_name(scenario_name)
    
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    # Issue identity for the scenario agent
    agent_id = scenario["agent_id"]
    identity = ta.issue_identity(agent_id)
    sidecar = AISidecar(identity, pe)
    
    results = []
    interventions = 0
    
    # Execute each event in the scenario
    for event in scenario["events"]:
        intent_data = {
            "name": event["intent"],
            **{k: v for k, v in event.items() if k not in ["intent", "expected_decision", "reason"]}
        }
        
        # Process the action through AEGIS
        result = sidecar.process_action(
            intent_data,
            environment="production",
            reasoning=event.get("reasoning")
        )
        
        # Log the decision
        ledger.log_decision(
            agent_id,
            event["intent"],
            result["decision"],
            result["reason"],
            result["signature"]
        )
        
        # Track interventions
        if result["decision"] == "DENY":
            interventions += 1
        
        results.append({
            "intent": event["intent"],
            "decision": result["decision"],
            "reason": result["reason"],
            "expected": event["expected_decision"],
            "matched": result["decision"] == event["expected_decision"]
        })
    
    # Update global stats
    with Session(engine) as session:
        stats = session.exec(select(GlobalStats)).first()
        if stats:
            stats.interventions += interventions
            session.add(stats)
            session.commit()
    
    return {
        "scenario": scenario["name"],
        "agent_id": agent_id,
        "severity": scenario["severity"],
        "outcome": scenario["outcome"],
        "forensic_notes": scenario["forensic_notes"],
        "events": results,
        "total_interventions": interventions,
        "success": all(r["matched"] for r in results)
    }
