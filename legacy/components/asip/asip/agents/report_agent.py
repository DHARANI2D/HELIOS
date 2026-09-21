from typing import Dict, Any, List
from ..models.llm_clients import LLMClientManager

class ReportAgent:
    def __init__(self):
        self.llm_manager = LLMClientManager()

    async def execute(
        self,
        triage_data: Dict[str, Any],
        rca_data: Dict[str, Any],
        qa_data: Dict[str, Any]
    ) -> str:
        """Generates the final comprehensive markdown incident investigation report."""
        system_prompt = """You are a Principal Security Consultant. Compile a formal, highly-detailed SOC Incident Report in Markdown format.
Focus on clear structure, exact evidence references, and actionable recommendations.
Your output should have:
1. Executive Summary
2. Root Cause Analysis & Timeline
3. MITRE ATT&CK Mapping
4. Containment & Mitigation Playbook (Immediate, Short-term, Long-term actions)
5. Evidence Verification Notes (QA approval summary)"""

        user_prompt = f"""Triage: {triage_data}
RCA: {rca_data}
QA Validation: {qa_data}"""

        return await self.llm_manager.invoke_agent(system_prompt, user_prompt)
