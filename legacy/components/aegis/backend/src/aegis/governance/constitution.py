from typing import Dict, Any, List

class AIConstitution:
    """The immutable safety layer of AEGIS. Rules that cannot be overridden by any policy."""
    
    Prohibitions = [
        "DELETE_SYSTEM_CORE",
        "ESCALATE_OWN_PRIVILEGE",
        "DISABLE_AEGIS_PROXY",
        "EXFILTRATE_ENCRYPTION_KEYS"
    ]

    @staticmethod
    def verify_invariant(intent: Dict[str, Any]) -> Dict[str, Any]:
        """Checks if an intent violates a constitutional invariant."""
        intent_name = intent.get("name", "").upper()
        
        if intent_name in AIConstitution.Prohibitions:
            return {
                "safe": False, 
                "violation": "CONSTITUTION_BREACH", 
                "reason": f"Intent {intent_name} is strictly prohibited by AI Constitution."
            }
            
        # Example of a behavioral invariant: 
        # No modification of certain protected filenames
        target = intent.get("target", "")
        if intent_name == "MODIFY_RESOURCE" and "/aegis/" in target.lower():
            return {
                "safe": False,
                "violation": "SELF_PROTECTION_FAULT",
                "reason": "AI is prohibited from modifying AEGIS core components."
            }
            
        return {"safe": True}
