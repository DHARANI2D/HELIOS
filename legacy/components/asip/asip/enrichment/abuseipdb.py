import urllib.request
import urllib.parse
import json
import asyncio
from typing import Dict, Any
from ..core.config import settings

class AbuseIPDBClient:
    def __init__(self):
        self.api_key = settings.ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2/check"

    async def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """Query AbuseIPDB for IP reputation."""
        if not self.api_key:
            return self._get_mock_result(ip_address)

        return await self._make_request(ip_address)

    async def _make_request(self, ip_address: str) -> Dict[str, Any]:
        def _sync_request():
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": "90"
            }
            url = f"{self.base_url}?{urllib.parse.urlencode(params)}"
            req = urllib.request.Request(url)
            req.add_header("Key", self.api_key)
            req.add_header("Accept", "application/json")
            
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    res_json = json.loads(response.read().decode('utf-8'))
                    data = res_json.get("data", {})
                    abuse_score = data.get("abuseConfidenceScore", 0)
                    country = data.get("countryName") or data.get("countryCode", "Unknown")
                    isp = data.get("isp", "Unknown")
                    
                    return {
                        "abuse_score": abuse_score,
                        "country": country,
                        "isp": isp,
                        "is_malicious": abuse_score > 25,
                        "details": f"AbuseIPDB Score: {abuse_score}% (Country: {country}, ISP: {isp})"
                    }
            except Exception as e:
                return {
                    "abuse_score": 0,
                    "country": "Unknown",
                    "isp": "Unknown",
                    "is_malicious": False,
                    "details": f"AbuseIPDB query failed: {str(e)}"
                }
        return await asyncio.to_thread(_sync_request)

    def _get_mock_result(self, ip_address: str) -> Dict[str, Any]:
        # Local mocking logic
        abuse_score = 0
        country = "US"
        isp = "Google Cloud Platform"
        is_malicious = False

        if ip_address == "185.220.101.5":  # Common Tor/C2 mock IP
            abuse_score = 85
            country = "NL"
            isp = "Tor Exit Node Provider"
            is_malicious = True

        return {
            "abuse_score": abuse_score,
            "country": country,
            "isp": isp,
            "is_malicious": is_malicious,
            "details": f"Mock AbuseIPDB Score: {abuse_score}% (Country: {country}, ISP: {isp}) [API Key Missing]"
        }
