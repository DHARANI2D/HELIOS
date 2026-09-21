import aiohttp
import logging
from app.core.config import settings

logger = logging.getLogger("uvicorn")

class AbuseIPDBClient:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or settings.abuse_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }

    async def check_ip(self, ip: str, max_age_days: int = 90, verbose: bool = True) -> dict:
        """
        Check an IP address against AbuseIPDB.
        """
        if not self.api_key:
            return {}

        endpoint = f"{self.base_url}/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": str(max_age_days)
        }
        if verbose:
            params["verbose"] = ""

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(endpoint, headers=self.headers, params=params) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        error_data = await resp.json()
                        logger.error(f"AbuseIPDB Check Error ({resp.status}): {error_data}")
        except Exception as e:
            logger.error(f"AbuseIPDB Connection Error: {e}")
        
        return {}

    async def get_reports(self, ip: str, max_age_days: int = 90, page: int = 1, per_page: int = 25) -> dict:
        """
        Get recent reports for an IP address.
        """
        if not self.api_key:
            return {}

        endpoint = f"{self.base_url}/reports"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": str(max_age_days),
            "page": str(page),
            "perPage": str(per_page)
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(endpoint, headers=self.headers, params=params) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception as e:
            logger.error(f"AbuseIPDB Reports Error: {e}")
        
        return {}

    async def report_ip(self, ip: str, categories: list[int], comment: str) -> dict:
        """
        Report an abusive IP address.
        Categories reference: https://www.abuseipdb.com/categories
        Common: 18 (Brute-Force), 19 (Bad Web Bot), 21 (Data Exfiltration), 22 (SSH Brute Force)
        """
        if not self.api_key:
            return {}

        endpoint = f"{self.base_url}/report"
        data = {
            "ip": ip,
            "categories": ",".join(map(str, categories)),
            "comment": comment
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(endpoint, headers=self.headers, data=data) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        error_data = await resp.json()
                        logger.error(f"AbuseIPDB Report Submission Error ({resp.status}): {error_data}")
        except Exception as e:
            logger.error(f"AbuseIPDB Submit Error: {e}")
        
        return {}

async def get_enhanced_ip_intel(ip: str) -> dict:
    """
    Enhanced IP intelligence using AbuseIPDB v2.
    """
    client = AbuseIPDBClient()
    check_data = await client.check_ip(ip)
    
    if not check_data:
        return {}

    data = check_data.get("data", {})
    return {
        "ip": data.get("ipAddress"),
        "is_public": data.get("isPublic"),
        "abuse_score": data.get("abuseConfidenceScore", 0),
        "country": data.get("countryName"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "usage_type": data.get("usageType"),
        "is_tor": data.get("isTor", False),
        "total_reports": data.get("totalReports", 0),
        "last_reported_at": data.get("lastReportedAt"),
        "recent_reports": data.get("reports", [])[:5] # Limit to top 5
    }
