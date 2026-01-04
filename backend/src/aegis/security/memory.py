import time
from typing import Dict, Any, List

class MemoryGovernance:
    """Controls AI memory persistence and contextual data exposure."""
    
    def __init__(self):
        self.memory_store: Dict[str, List[Dict[str, Any]]] = {} # ai_id -> memory_blocks

    def protect_memory(self, ai_id: str, memory_block: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enforce Memory Policies:
        1. TTL: Clear sensitive memory after X seconds.
        2. Sensitivity Scoping: Redact PII from memory writes.
        """
        # Example Policy: No PII in persistent memory
        data = memory_block.get("data", "")
        if any(kw in data.lower() for kw in ["password", "token", "ssn", "secret"]):
            return {"safe": False, "reason": "SECURITY_VIOLATION: No credentials allowed in AI memory."}
            
        # Add metadata
        memory_block["timestamp"] = time.time()
        memory_block["ttl"] = 3600 # 1 hour default
        
        if ai_id not in self.memory_store:
            self.memory_store[ai_id] = []
        self.memory_store[ai_id].append(memory_block)
        
        return {"safe": True, "block_id": len(self.memory_store[ai_id])}

    def minimize_context(self, raw_data: str, task_intent: str) -> str:
        """
        Structural Data Minimization:
        Only show the AI what it needs to see.
        """
        # Simplified Logic: If intent is 'REFACTOR', don't show ENV variables/secrets.
        if "REFACTOR" in task_intent.upper() and "API_KEY" in raw_data:
            return "[REDACTED_CONTEXT_FOR_MINIMIZATION]"
        return raw_data
