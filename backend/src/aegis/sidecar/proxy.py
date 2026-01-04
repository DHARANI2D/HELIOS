import json
from typing import Dict, Any, List
from aegis.identity.idp import AIIdentity
from aegis.policy.engine import PolicyEvaluator
from aegis.governance.constitution import AIConstitution
from aegis.security.reasoning import ReasoningMonitor

class AISidecar:
    """The enforcement sidecar that sits next to the AI Agent (Advanced Tier)."""
    
    def __init__(self, identity: AIIdentity, policy_engine: PolicyEvaluator):
        self.identity = identity
        self.policy_engine = policy_engine
        self.reasoning_monitor = ReasoningMonitor()
        self.mode = "NORMAL"
        
    def process_action(self, action_request: Dict[str, Any], environment: str, ctrl_plane_reachable: bool = True, reasoning: List[str] = None) -> Dict[str, Any]:
        """
        The proxy pipeline (Advanced):
        1. Constitutional Check
        2. Reasoning Integrity Check (Drift & Hallucination)
        3. Fail-Closed Check
        4. Identity Tagging
        5. Policy Evaluation
        """
        # 1. Constitutional Check (Immutable safety)
        const_check = AIConstitution.verify_invariant(action_request)
        if not const_check["safe"]:
            return self._format_response(action_request, "DENY", f"[CONSTITUTION] {const_check['reason']}")

        # 2. Reasoning Integrity Check (Logic Drift)
        if reasoning:
            reasoning_check = self.reasoning_monitor.analyze_reasoning(self.identity.ai_id, reasoning, action_request.get("name", ""))
            if not reasoning_check["safe"]:
                return self._format_response(action_request, "DENY", f"[REASONING_FAULT] {reasoning_check['reason']}")
            
            # Hash reasoning for bit-perfect audit/replay
            action_request["reasoning_hash"] = self.reasoning_monitor.generate_reasoning_hash(reasoning)

        # 3. Fail-Closed Logic (Network Resilience)
        if not ctrl_plane_reachable:
            is_risky = any(kw in action_request.get("name", "").upper() for kw in ["DELETE", "MODIFY", "EXECUTE"])
            if is_risky:
                return self._format_response(action_request, "DENY", "FAIL_CLOSED: Control plane unreachable. Destructive actions blocked.")
            return self._format_response(action_request, "ALLOW", "FAIL_SAFE: Proceeding with low-risk action (cached/default).")

        # 4. Identity Tagging & Policy Evaluation
        message = json.dumps(action_request, sort_keys=True).encode()
        signature = self.identity.sign_message(message)
        
        context = {
            "ai_identity": {"id": self.identity.ai_id, "signature": signature},
            "intent": action_request,
            "environment": environment
        }
        
        evaluation = self.policy_engine.evaluate(context)
        
        return self._format_response(action_request, evaluation["decision"], evaluation["reason"], signature)

    def _format_response(self, req: Dict[str, Any], decision: str, reason: str, signature: str = None) -> Dict[str, Any]:
        return {
            "ai_id": self.identity.ai_id,
            "action": req.get("name"),
            "decision": decision,
            "reason": reason,
            "signature": signature or "UNAVAILABLE",
            "reasoning_hash": req.get("reasoning_hash", "NONE")
        }
