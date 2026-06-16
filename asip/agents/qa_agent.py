import json
from typing import Dict, Any, List
from ..models.llm_clients import LLMClientManager

class QAAgent:
    def __init__(self):
        self.llm_manager = LLMClientManager()

    async def execute(
        self,
        rca_data: Dict[str, Any],
        sample_logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Critically inspect the RCA findings and assert truthfulness against raw log event records."""
        system_prompt = """You are an Adversarial QA Security Validator. Your job is to verify that the Root Cause Analysis is factually correct.
Verify:
1. Every claim in root_cause or timeline corresponds to an actual event in the logs.
2. The sequence of events makes chronological sense.
Return a JSON object with the following fields:
{
  "is_valid": true/false,
  "validated_evidence": [
     "List of claims that are confirmed by specific log lines (with timestamps, process names, PIDs)"
  ],
  "issues": [
     "List of problems found (e.g. 'Timeline claims powershell.exe connected at 08:01:34, but network log says connection happened at 08:00:10, before process execution')"
  ]
}
Ensure the output is valid JSON and nothing else."""

        logs_summary = sample_logs[:50]
        
        user_prompt = f"""RCA Report: {json.dumps(rca_data, indent=2)}
Ingested Logs: {json.dumps(logs_summary, indent=2)}"""

        try:
            raw_res = await self.llm_manager.invoke_agent(system_prompt, user_prompt, schema={"type": "json"})
            cleaned_res = raw_res.strip().replace("```json", "").replace("```", "")
            return json.loads(cleaned_res)
        except Exception as e:
            return {
                "is_valid": False,
                "validated_evidence": [],
                "issues": [f"QA verification failed: {str(e)}"]
            }
