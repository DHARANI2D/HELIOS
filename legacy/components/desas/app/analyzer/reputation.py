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

    # 1. Enhanced AbuseIPDB (v2)
    from app.analyzer.abuseipdb import get_enhanced_ip_intel
    try:
        abuse_data = await get_enhanced_ip_intel(ip)
        if abuse_data:
            intel["reputation"] = abuse_data
            intel["abuse_score"] = abuse_data.get("abuse_score", 0)
            intel["country_code"] = abuse_data.get("country_code")
            intel["country_name"] = abuse_data.get("country")
            intel["isp"] = abuse_data.get("isp")
            intel["domain"] = abuse_data.get("domain")
            intel["reports"] = abuse_data.get("total_reports", 0) # Alias for frontend
    except Exception as e:
        import logging
        logging.getLogger("uvicorn").error(f"Error in AbuseIPDB integration: {e}")

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
