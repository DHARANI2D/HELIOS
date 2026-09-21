import os
import yaml
from typing import Dict, Any, Optional

class PolicyEvaluator:
    """Evaluates AI intents against defined policies."""
    
    def __init__(self, intents_path: str):
        # Resolve path: if not absolute, check relative to this file's directory
        if not os.path.isabs(intents_path):
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            intents_path = os.path.join(base_dir, "policy", "intents.yaml")
            
        with open(intents_path, 'r') as f:
            self.taxonomy = yaml.safe_load(f)
            
    def evaluate(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decision Logic:
        1. Check if intent exists in taxonomy
        2. Validate required fields
        3. Evaluate risk & confidence
        4. Check environment constraints
        """
        intent_name = context.get("intent", {}).get("name")
        environment = context.get("environment", "unknown")
        confidence = context.get("intent", {}).get("confidence", 0.0)
        
        # 1. Find intent definition
        intent_def = next((i for i in self.taxonomy['intents'] if i['name'] == intent_name), None)
        if not intent_def:
            return {"decision": "DENY", "reason": f"Unknown intent: {intent_name}"}
            
        # 2. Risk Evaluation
        risk_level = intent_def['risk_level']
        constraints = self.taxonomy['constraints']
        env_defaults = constraints['environment_defaults'].get(environment, {})
        
        # 3. Decision Logic (MVP Implementation of rules.py logic)
        if confidence < constraints['confidence_threshold']:
            return {"decision": "DENY", "reason": "Confidence too low"}
            
        if env_defaults.get("human_approval_required") and risk_level in ["HIGH", "CRITICAL"]:
            return {"decision": "ESCALATE", "reason": "Human approval required for high risk in production"}
            
        if environment == "production" and risk_level == "CRITICAL":
             return {"decision": "DENY", "reason": "Critical actions blocked in production by default"}

        return {"decision": "ALLOW", "reason": "Policy requirements met"}
