import aiohttp
from app.core.config import settings

async def query_mxtoolbox(domain: str, dkim_selector: str = None) -> dict:
    """
    Queries MxToolbox for expanded diagnostics (Mx, SPF, DMARC, DKIM, Blacklist).
    Returns a dictionary with specific findings for display.
    """
    if not settings.MXTOOLBOX_API_KEY or not domain:
        return {}

    base_url = "https://api.mxtoolbox.com/mxtoolbox/v0/check"
    headers = {"Authorization": settings.MXTOOLBOX_API_KEY}
    
    # Structure: Key -> {passed: bool, details: List[{name, status, info}]}
    results = {
        "mx": {"passed": True, "details": []},
        "blacklist": {"passed": True, "details": []},
        "spf": {"passed": True, "details": []},
        "dkim": {"passed": True, "details": [], "checked": False},
        "dmarc": {"passed": True, "details": []},
        "dns": {"passed": True, "details": []},
        "smtp": {"passed": True, "details": []}
    }

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            
            async def run_check(cmd, arg, result_key):
                 async with session.get(f"{base_url}/{cmd}/{arg}") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        monitor_passed = True
                        
                        # Process "Failed"
                        for item in data.get("Failed", []):
                            monitor_passed = False
                            results[result_key]["details"].append({
                                "name": item.get("Name", "Error"),
                                "status": "FAIL",
                                "info": item.get("Description", "")
                            })
                        
                        # Process "Passed"
                        for item in data.get("Passed", []):
                            results[result_key]["details"].append({
                                "name": item.get("Name", "Info"),
                                "status": "PASS",
                                "info": item.get("Description") or item.get("Information", "")
                            })

                        # Process "Information"
                        for item in data.get("Information", []):
                             results[result_key]["details"].append({
                                "name": item.get("Name", "Info"),
                                "status": "INFO",
                                "info": item.get("Description") or item.get("Information", "")
                            })

                        if not monitor_passed:
                            results[result_key]["passed"] = False

            # Run all 7 monitors
            await run_check("mx", domain, "mx")
            await run_check("blacklist", domain, "blacklist")
            await run_check("spf", domain, "spf")
            await run_check("dmarc", domain, "dmarc")
            await run_check("dns", domain, "dns")
            await run_check("smtp", domain, "smtp")
            
            # DKIM (conditional)
            if dkim_selector:
                results["dkim"]["checked"] = True
                await run_check("dkim", f"{domain}:{dkim_selector}", "dkim")

    except Exception as e:
        results["error"] = str(e)

    return results

    return results
