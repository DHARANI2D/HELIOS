from typing import Dict, Any

class ContasLevel:
    """The 10-level Containment Status scale for AEGIS."""
    LEVELS = {
        10: "UNRESTRICTED",
        9:  "MONITORED",
        8:  "THROTTLED_10PCT",
        7:  "READ_ONLY_STAGING",
        6:  "READ_ONLY_GLOBAL",
        5:  "APPROVAL_REQUIRED_ALL",
        4:  "SANDBOX_ONLY",
        3:  "SHADOW_MODE",      # No real actions, only logs
        2:  "MOCK_RESPONSES",   # Return dummy data
        1:  "TOTAL_LOCKDOWN"    # Kill-switch
    }

class ProgressiveIsolationEngine:
    """Manages granular containment based on the Contas scale."""
    
    def __init__(self):
        self.agent_levels: Dict[str, int] = {}

    def get_contas_level(self, trust_score: float) -> int:
        """Maps 0-100 trust to 1-10 Contas level."""
        return max(1, min(10, int(trust_score / 10) + 1))

    def check_capability(self, ai_id: str, trust_score: float, intent_name: str) -> Dict[str, Any]:
        level = self.get_contas_level(trust_score)
        self.agent_levels[ai_id] = level
        
        status = ContasLevel.LEVELS[level]
        
        # 1. Level 1: Hard Lockdown
        if level <= 1:
            return {"allowed": False, "level": level, "status": status, "reason": "TOTAL_LOCKDOWN: Identity revoked."}
            
        # 2. Level 2-3: Non-operational modes
        if level <= 3:
            return {"allowed": False, "level": level, "status": status, "reason": f"Agent in {status} mode. Real actions disabled."}
            
        # 3. Level 4-6: Read-only / Sandbox
        is_write = any(kw in intent_name.upper() for kw in ["MODIFY", "DELETE", "EXECUTE"])
        if level <= 6 and is_write:
            return {"allowed": False, "level": level, "status": status, "reason": f"Write action {intent_name} blocked in {status} mode."}
            
        return {"allowed": True, "level": level, "status": status, "reason": "Capability within trust boundaries."}
