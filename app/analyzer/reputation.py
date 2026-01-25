import aiohttp
from app.core.config import settings

async def get_ip_intel(ip: str) -> dict:
    """
    Fetches IP Reputation (AbuseIPDB) and Geo-Location (ip-api.com).
    """
    intel = {
        "reputation": {},
        "geo": {},
        "abuse_score": 0
    }

    if not ip or ip == "unknown":
        return intel

    # 1. AbuseIPDB
    if settings.abuse_key:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"Key": settings.abuse_key, "Accept": "application/json"}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        details = data.get("data", {})
                        intel["reputation"] = {
                            "abuse_score": details.get("abuseConfidenceScore", 0),
                            "isp": details.get("isp"),
                            "usage_type": details.get("usageType"),
                            "reports": details.get("totalReports", 0)
                        }
                        intel["abuse_score"] = details.get("abuseConfidenceScore", 0)
        except Exception:
            pass

    # 2. Geo-Location (Free API)
    try:
        url = f"http://ip-api.com/json/{ip}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        intel["geo"] = {
                            "country": data.get("country"),
                            "city": data.get("city"),
                            "org": data.get("org"),
                            "as": data.get("as")
                        }
    except Exception:
        pass

    return intel
