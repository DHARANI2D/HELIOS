from typing import Dict, Any, List
import json
from ..models.llm_clients import LLMClientManager

class TriageAgent:
    def __init__(self):
        self.llm_manager = LLMClientManager()

    async def execute(self, alert_title: str, alert_details: str) -> Dict[str, Any]:
        """Triage the alert, categorize the threat, and identify forensic search context."""
        system_prompt = """You are a Tier 3 SOC Analyst. Your task is to triage and categorize the incoming cybersecurity alert.
Return a JSON object with the following fields:
{
  "alert_type": "string (e.g. Encoded PowerShell, Suspicious Login)",
  "severity": "string (critical, high, medium, low)",
  "mitre_tactic": "string (e.g. Execution TA0002)",
  "initial_hypothesis": "string (describe how this happened and likely parent-child processes)",
  "evidence_required": ["list of strings indicating what logs we need to search for (e.g. process_create, network_connect)"]
}
Ensure the output is valid JSON and nothing else."""

        user_prompt = f"Alert Title: {alert_title}\nAlert Details: {alert_details}"
        
        try:
            raw_res = await self.llm_manager.invoke_agent(system_prompt, user_prompt, schema={"type": "json"})
            # Extract JSON cleanly in case the model returns markdown ticks
            cleaned_res = raw_res.strip().replace("```json", "").replace("```", "")
            return json.loads(cleaned_res)
        except Exception as e:
            return {
                "alert_type": "Suspicious Threat Alert",
                "severity": "high",
                "mitre_tactic": "Unknown Tactic",
                "initial_hypothesis": f"Error parsing triage reasoning: {str(e)}",
                "evidence_required": ["process_create", "network_connect"]
            }
