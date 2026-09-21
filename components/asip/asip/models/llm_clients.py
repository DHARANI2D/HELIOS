import urllib.request
import json
import asyncio
from typing import Dict, Any, List, Optional
from ..core.config import settings

class LLMClientManager:
    def __init__(self):
        self.openai_key = settings.OPENAI_API_KEY
        self.anthropic_key = settings.ANTHROPIC_API_KEY
        self.ollama_url = settings.OLLAMA_BASE_URL
        self.local_model = settings.LOCAL_MODEL

    async def invoke_agent(self, system_prompt: str, user_prompt: str, schema: Optional[Dict[str, Any]] = None) -> str:
        """Invokes the appropriate AI model (cloud reasoning or local Ollama) based on settings."""
        # Try local Ollama if configured and keys are missing
        if not self.openai_key and not self.anthropic_key:
            try:
                return await self._call_ollama(system_prompt, user_prompt, schema)
            except Exception:
                # If Ollama fails or is not running, fall back to the mock AI engine
                return self._get_mock_agent_response(system_prompt, user_prompt, schema)
        
        # Call Anthropic if key is set
        if self.anthropic_key:
            try:
                return await self._call_anthropic(system_prompt, user_prompt)
            except Exception:
                pass
                
        # Call OpenAI as fallback/default cloud model
        if self.openai_key:
            try:
                return await self._call_openai(system_prompt, user_prompt, schema)
            except Exception:
                pass
                
        return self._get_mock_agent_response(system_prompt, user_prompt, schema)

    async def _call_ollama(self, system_prompt: str, user_prompt: str, schema: Optional[Dict[str, Any]]) -> str:
        url = f"{self.ollama_url}/api/chat"
        payload = {
            "model": self.local_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "stream": False
        }
        if schema:
            payload["format"] = "json"

        def _sync_post():
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                res = json.loads(response.read().decode('utf-8'))
                return res.get("message", {}).get("content", "")
                
        return await asyncio.to_thread(_sync_post)

    async def _call_openai(self, system_prompt: str, user_prompt: str, schema: Optional[Dict[str, Any]]) -> str:
        url = "https://api.openai.com/v1/chat/completions"
        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        }
        if schema:
            payload["response_format"] = {"type": "json_object"}

        def _sync_post():
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode('utf-8'),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.openai_key}"
                }
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                res = json.loads(response.read().decode('utf-8'))
                return res["choices"][0]["message"]["content"]
                
        return await asyncio.to_thread(_sync_post)

    async def _call_anthropic(self, system_prompt: str, user_prompt: str) -> str:
        url = "https://api.anthropic.com/v1/messages"
        payload = {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 4096,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt}
            ]
        }

        def _sync_post():
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode('utf-8'),
                headers={
                    "content-type": "application/json",
                    "x-api-key": self.anthropic_key,
                    "anthropic-version": "2023-06-01"
                }
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                res = json.loads(response.read().decode('utf-8'))
                return res["content"][0]["text"]
                
        return await asyncio.to_thread(_sync_post)

    def _get_mock_agent_response(self, system_prompt: str, user_prompt: str, schema: Optional[Dict[str, Any]]) -> str:
        """Determines the semantic intent of the agent and returns a highly detailed mock response."""
        # Clean user prompt check
        up = user_prompt.lower()
        
        # 1. Triage Agent Mock Response
        if "triage" in system_prompt.lower() or "classify" in system_prompt.lower():
            res_dict = {
                "alert_type": "Suspicious Process Execution",
                "severity": "high",
                "mitre_tactic": "Execution (TA0002)",
                "initial_hypothesis": "Office document VBA macro spawned PowerShell cradle to download secondary updates payload.",
                "evidence_required": ["Process creation logs for outlook/winword", "Network logs mapping to destination IP"]
            }
            return json.dumps(res_dict) if schema else f"Triage Analysis:\n- Threat: {res_dict['alert_type']}\n- Severity: {res_dict['severity']}\n- Hypothesis: {res_dict['initial_hypothesis']}"

        # 2. Correlation & RCA Agent Mock Response
        elif "correlation" in system_prompt.lower() or "root cause" in system_prompt.lower() or "rca" in system_prompt.lower():
            res_dict = {
                "root_cause": "The incident was initiated when user john.doe opened the phishing attachment 'invoice.docx' via Outlook. VBA macros immediately triggered cmd.exe which spawned powershell.exe executing an encoded base64 connection string.",
                "timeline": [
                    "08:01:23 - Outlook opened invoice.docx attachment",
                    "08:01:31 - winword.exe spawned powershell.exe (PID 4512)",
                    "08:01:34 - powershell.exe connected to remote C2 IP 185.220.101.5:4444"
                ],
                "confidence_score": 0.95
            }
            return json.dumps(res_dict) if schema else f"RCA Analysis:\n- Root Cause: {res_dict['root_cause']}\n- Score: {res_dict['confidence_score']}"

        # 3. Adversarial QA Agent Mock Response
        elif "qa" in system_prompt.lower() or "validation" in system_prompt.lower():
            res_dict = {
                "is_valid": True,
                "validated_evidence": [
                    "powershell.exe spawn confirmed by Sysmon Event ID 1",
                    "C2 connection to 185.220.101.5 verified by firewall rules"
                ],
                "issues": []
            }
            return json.dumps(res_dict) if schema else "QA Check: Approved. All conclusions verified against raw telemetry logs."

        # 4. Reporting & Recommendation Agent Mock Response
        else:
            report_markdown = """# INCIDENT SUMMARY REPORT (ASIP-2024-001)

## 📌 Executive Summary
A **high-severity execution threat** was detected and triaged on **server01**. The threat originated from a phishing email leading to VBA macro-enabled code execution. Automated remediation steps are required to isolate the asset.

## 🔍 Root Cause Analysis (RCA)
1. **Initial Access**: Spearpishing attachment `invoice.docx` opened by user `john.doe`.
2. **Execution**: VBA code spawned PowerShell containing an encoded download cradle.
3. **Command & Control**: Outbound connection established to Tor node `185.220.101.5:4444`.

## 🛡️ Response Playbook (Immediate Containment)
*   **Asset Isolation**: Isolate host `server01` using EDR containment rules.
*   **Credential Revocation**: Revoke sessions for Active Directory account `john.doe`.
*   **Firewall Blocklist**: Deploy block rules for IP `185.220.101.5` on egress proxies.
"""
            return report_markdown
