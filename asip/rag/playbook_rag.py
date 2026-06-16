from typing import List, Dict, Any
from .vector_store import VectorStoreManager

class PlaybookRAGManager:
    def __init__(self):
        self.vector_store = VectorStoreManager()
        self.playbooks_collection = "playbooks"
        self.mitre_collection = "mitre"

    async def initialize_knowledge_bases(self):
        """Pre-populates vector databases with common MITRE techniques and corporate containment playbooks."""
        # 1. Common Incident playbooks
        playbooks = [
            {
                "id": 101,
                "text": "Playbook: Suspicious Process Execution & PowerShell Cradle. Immediate containment: Isolate the host from the network. short term: revoke Active Directory sessions. long term: block Office application spawning shells.",
                "payload": {"type": "containment", "tactic": "Execution"}
            },
            {
                "id": 102,
                "text": "Playbook: Phishing Email & Macro Execution. Immediate containment: Revoke active O365 logins. short term: search email headers for attachment hash, purge malicious emails from all mailboxes. long term: restrict macro usage via Group Policy.",
                "payload": {"type": "containment", "tactic": "Initial Access"}
            },
            {
                "id": 103,
                "text": "Playbook: Outbound Connection to Malicious/Tor IP (C2 beacon). Immediate containment: Deploy egress proxy block rule for IP/domain. short term: trace process establishing the socket connection and terminate process. long term: enable DNS threat protection filter.",
                "payload": {"type": "containment", "tactic": "Command & Control"}
            }
        ]
        await self.vector_store.upsert_documents(self.playbooks_collection, playbooks)

        # 2. Key MITRE ATT&CK techniques
        mitre_techniques = [
            {
                "id": 201,
                "text": "T1566.001 - Spearphishing Attachment: Phishing emails delivering malicious documents containing embedded payloads (VBA macro, exploit code) to gain Initial Access.",
                "payload": {"technique_id": "T1566.001", "name": "Spearphishing Attachment"}
            },
            {
                "id": 202,
                "text": "T1059.001 - PowerShell: Interactive commandline and scripting utility commonly used to execute commands, retrieve remote payload scripts, or perform discovery in memory.",
                "payload": {"technique_id": "T1059.001", "name": "PowerShell"}
            },
            {
                "id": 203,
                "text": "T1547.001 - Registry Run Keys / Startup Folder: Modifying registry hive keys under CurrentVersion\\Run or dropped files in Startup folder to maintain persistence across system reboots.",
                "payload": {"technique_id": "T1547.001", "name": "Registry Run Keys / Startup Folder"}
            },
            {
                "id": 204,
                "text": "T1071.001 - Application Layer Protocol (Web Protocols): Communicating command and control traffic over standard HTTP/HTTPS channels to blend in with legitimate enterprise network telemetry.",
                "payload": {"technique_id": "T1071.001", "name": "Web Protocols"}
            }
        ]
        await self.vector_store.upsert_documents(self.mitre_collection, mitre_techniques)

    async def get_recommended_playbooks(self, tactic_or_behavior: str) -> List[Dict[str, Any]]:
        """Finds playbooks related to the incident behavior description."""
        try:
            return await self.vector_store.query_similarity(self.playbooks_collection, tactic_or_behavior, limit=2)
        except Exception:
            return []

    async def match_mitre_techniques(self, behavior_description: str) -> List[Dict[str, Any]]:
        """Maps threat behavior descriptions to closest MITRE ATT&CK techniques."""
        try:
            return await self.vector_store.query_similarity(self.mitre_collection, behavior_description, limit=2)
        except Exception:
            return []
