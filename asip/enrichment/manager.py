from typing import Dict, Any, Optional
from .virustotal import VirusTotalClient
from .abuseipdb import AbuseIPDBClient

class EnrichmentManager:
    def __init__(self):
        self.vt_client = VirusTotalClient()
        self.abuse_client = AbuseIPDBClient()

    async def enrich_ioc(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """
        Enrich an IOC indicator with reputation and classification info.
        Returns a dictionary that matches the fields in the IOC database model.
        """
        result = {
            "vt_score": None,
            "vt_malicious_count": 0,
            "abuseipdb_score": 0,
            "otx_pulse_count": 0,
            "threat_actor": None,
            "malware_family": None,
            "confidence": 0.5,
            "context": "Enriched via threat feed lookup."
        }

        try:
            if ioc_type == "ipv4":
                # Run lookups concurrently to optimize performance
                import asyncio
                vt_task = self.vt_client.enrich_ip(value)
                abuse_task = self.abuse_client.enrich_ip(value)
                
                vt_res, abuse_res = await asyncio.gather(vt_task, abuse_task, return_exceptions=True)
                
                if not isinstance(vt_res, Exception):
                    result["vt_malicious_count"] = vt_res.get("malicious_count", 0)
                    result["vt_score"] = vt_res.get("reputation_score")
                    if vt_res.get("is_malicious"):
                        result["confidence"] = 0.9
                        result["threat_actor"] = "Unknown Threat Group"
                
                if not isinstance(abuse_res, Exception):
                    result["abuseipdb_score"] = abuse_res.get("abuse_score", 0)
                    if abuse_res.get("is_malicious"):
                        result["confidence"] = max(result["confidence"], 0.85)
                        
                result["context"] = f"IP analysis. VT: {result['vt_score'] or 'N/A'}. AbuseIPDB: {result['abuseipdb_score']}%."

            elif ioc_type == "domain" or ioc_type == "url":
                vt_res = await self.vt_client.enrich_domain(value) if ioc_type == "domain" else await self.vt_client.enrich_domain(value)
                result["vt_malicious_count"] = vt_res.get("malicious_count", 0)
                result["vt_score"] = vt_res.get("reputation_score")
                if vt_res.get("is_malicious"):
                    result["confidence"] = 0.9
                    result["threat_actor"] = "Phishing Candidate / C2 Domain"
                result["context"] = f"Domain lookup. VT: {result['vt_score'] or 'N/A'}."

            elif ioc_type in ("sha256", "sha1", "md5"):
                vt_res = await self.vt_client.enrich_hash(value)
                result["vt_malicious_count"] = vt_res.get("malicious_count", 0)
                result["vt_score"] = vt_res.get("reputation_score")
                if vt_res.get("is_malicious"):
                    result["confidence"] = 0.95
                    result["malware_family"] = "Potential Malware Agent"
                result["context"] = f"File hash lookup. VT: {result['vt_score'] or 'N/A'}."

        except Exception as e:
            result["context"] = f"Enrichment lookup encountered an error: {str(e)}"

        return result
