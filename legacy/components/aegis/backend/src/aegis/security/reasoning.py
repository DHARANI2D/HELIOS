import hashlib
from typing import List, Dict, Any

class ReasoningMonitor:
    """Monitors AI reasoning quality and detects goal drift or hallucinations."""
    
    def __init__(self):
        self.reasoning_history: Dict[str, List[str]] = {}

    def analyze_reasoning(self, ai_id: str, reasoning_chain: List[str], final_intent: str) -> Dict[str, Any]:
        """
        Analyzes the logic:
        1. Consistency: Does the reasoning actually lead to the intent?
        2. Goal Drift: Does the AI change its goal mid-reasoning?
        3. Hallucination: Are there wild leaps in logic?
        """
        # MVP Implementation: Basic consistency check
        # In production, this would use a small 'Judge LLM' or embedding-based similarity
        
        # 1. Goal Drift Check
        keywords_in_reasoning = [r.lower() for r in reasoning_chain]
        intent_lower = final_intent.lower()
        
        # Check if the core intent keywords are present in the reasoning
        supported = any(intent_lower in r for r in keywords_in_reasoning)
        
        if not supported:
            return {
                "safe": False,
                "threat": "GOAL_DRIFT",
                "reason": "Final intent not supported by the reasoning chain."
            }
            
        # 2. Logic Skip Check (Basic length check)
        if len(reasoning_chain) < 2:
            return {
                "safe": False,
                "threat": "LOW_REASONING_QUALITY",
                "reason": "Insufficient reasoning steps to justify action."
            }
            
        return {"safe": True}

    def generate_reasoning_hash(self, reasoning: List[str]) -> str:
        """Create a tamper-evident hash of the AI's logical path."""
        combined = "|".join(reasoning)
        return hashlib.sha256(combined.encode()).hexdigest()
