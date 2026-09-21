from typing import Dict, Any, List
from aegis.policy.engine import PolicyEvaluator
from aegis.audit.ledger import AuditLedger

class DecisionReplayer:
    """Reconstructs and re-evaluates past AI decisions for forensic audit."""
    
    def __init__(self, policy_engine: PolicyEvaluator, ledger: AuditLedger):
        self.policy_engine = policy_engine
        self.ledger = ledger

    def replay_decision(self, current_hash: str) -> Dict[str, Any]:
        """Finds a decision by hash in the ledger and re-evaluates it."""
        logs = self.ledger.get_logs()
        target_log = next((l for l in logs if l.get("current_hash") == current_hash), None)
        
        if not target_log:
            return {"status": "ERROR", "reason": "Decision not found in ledger."}
            
        context = {
            "ai_identity": {"id": target_log["ai_id"], "signature": target_log["signature"]},
            "intent": {"name": target_log["intent"]},
            "environment": "production" # Default for re-evaluation
        }
        
        reevaluation = self.policy_engine.evaluate(context)
        
        return {
            "original_decision": target_log["decision"],
            "reevaluated_decision": reevaluation["decision"],
            "reason": reevaluation["reason"],
            "consistency": target_log["decision"] == reevaluation["decision"]
        }
