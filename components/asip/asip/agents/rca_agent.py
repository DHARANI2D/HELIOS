import json
from typing import Dict, Any, List
from ..models.llm_clients import LLMClientManager

class RCAAgent:
    def __init__(self):
        self.llm_manager = LLMClientManager()

    async def execute(
        self,
        triage_data: Dict[str, Any],
        graph_data: Dict[str, Any],
        sample_logs: List[Dict[str, Any]],
        similar_incidents: Optional[List[Dict[str, Any]]] = None,
        recommended_playbooks: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Correlate logs, process tree, and build Chain-of-Thought Root Cause Analysis."""
        system_prompt = """You are a Lead Incident Responder. Your task is to perform a detailed Root Cause Analysis (RCA) on the forensic graph and raw logs.
Connect the nodes chronologically to explain the attack vector.
If provided, refer to similar past incidents and standard containment playbooks to inform your thesis.
Return a JSON object with the following fields:
{
  "root_cause": "Detailed explanation of the initial entry point, process executions, and malicious connections.",
  "timeline": [
     "HH:MM:SS - Description of event with log reference (e.g. PID 4512 powershell connected to 185.220.101.5)"
  ],
  "confidence_score": 0.95
}
Ensure the output is valid JSON and nothing else."""

        # Truncate logs if too large to fit context
        logs_summary = sample_logs[:50]
        
        user_prompt = f"""Triage Assessment: {json.dumps(triage_data, indent=2)}
Forensic Graph: {json.dumps(graph_data, indent=2)}
Ingested Logs: {json.dumps(logs_summary, indent=2)}
Similar Past Incidents: {json.dumps(similar_incidents or [], indent=2)}
Standard Containment Playbooks: {json.dumps(recommended_playbooks or [], indent=2)}"""

        try:
            raw_res = await self.llm_manager.invoke_agent(system_prompt, user_prompt, schema={"type": "json"})
            cleaned_res = raw_res.strip().replace("```json", "").replace("```", "")
            return json.loads(cleaned_res)
        except Exception as e:
            return {
                "root_cause": f"Failed to perform RCA reasoning: {str(e)}",
                "timeline": ["00:00:00 - Timeline parsing failed"],
                "confidence_score": 0.5
            }
