import urllib.request
import json
import asyncio
from typing import Dict, Any, Optional
from ..core.config import settings

class VirusTotalClient:
    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"

    async def enrich_hash(self, file_hash: str) -> Dict[str, Any]:
        """Query VirusTotal for a file hash reputation."""
        if not self.api_key:
            return self._get_mock_result(file_hash, "file")
            
        url = f"{self.base_url}/files/{file_hash}"
        return await self._make_request(url)

    async def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """Query VirusTotal for an IP address reputation."""
        if not self.api_key:
            return self._get_mock_result(ip_address, "ip")
            
        url = f"{self.base_url}/ip_addresses/{ip_address}"
        return await self._make_request(url)

    async def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Query VirusTotal for a domain reputation."""
        if not self.api_key:
            return self._get_mock_result(domain, "domain")
            
        url = f"{self.base_url}/domains/{domain}"
        return await self._make_request(url)

    async def _make_request(self, url: str) -> Dict[str, Any]:
        def _sync_request():
            req = urllib.request.Request(
                url,
                headers={"x-apikey": self.api_key}
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    data = json.loads(response.read().decode('utf-8'))
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values())
                    
                    return {
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "total_scanners": total,
                        "reputation_score": f"{malicious}/{total}",
                        "is_malicious": malicious > 3,
                        "details": f"VirusTotal: {malicious} engines flagged this indicator as malicious."
                    }
            except Exception as e:
                return {
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "total_scanners": 0,
                    "reputation_score": "error",
                    "is_malicious": False,
                    "details": f"VirusTotal Query Failed: {str(e)}"
                }
        return await asyncio.to_thread(_sync_request)

    def _get_mock_result(self, value: str, ioc_type: str) -> Dict[str, Any]:
        # For local testing, mock typical results for common malicious indicators
        is_suspicious_mock = False
        details = "VirusTotal API key is not configured. Returning unverified mock status."
        malicious_count = 0
        
        # Mock detections for standard test/malicious values
        if "185.220.101.5" in value or "update-service.net" in value or "sha256_abc" in value:
            is_suspicious_mock = True
            malicious_count = 14
            details = "Mock threat flag: This indicator matches known threat behaviors in test datasets."

        return {
            "malicious_count": malicious_count,
            "suspicious_count": 0,
            "total_scanners": 70,
            "reputation_score": f"{malicious_count}/70" if is_suspicious_mock else "0/70",
            "is_malicious": is_suspicious_mock,
            "details": details
        }
