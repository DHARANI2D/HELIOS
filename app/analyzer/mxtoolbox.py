import aiohttp
from app.core.config import settings

async def query_mxtoolbox(domain: str, dkim_selector: str = None) -> dict:
    """
    Queries MxToolbox for expanded diagnostics (Mx, SPF, DMARC, DKIM, Blacklist).
    Returns a dictionary with specific findings for display.
    """
    if not settings.mx_key or not domain:
        return {}

    base_url = "https://api.mxtoolbox.com/api/v1/lookup"
    headers = {
        "Authorization": settings.mx_key,
        "Accept": "application/json"
    }
    
    # Structure: Key -> {passed: bool, details: List[{name, status, info}]}
    results = {
        "mx": {"passed": False, "details": []},
        "blacklist": {"passed": False, "details": []},
        "spf": {"passed": False, "details": []},
        "dkim": {"passed": False, "details": [], "checked": False},
        "dmarc": {"passed": False, "details": []},
        "dns": {"passed": False, "details": []},
        "smtp": {"passed": False, "details": []}
    }

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            
            async def run_check(cmd, arg, result_key):
                 try:
                     async with session.get(f"{base_url}/{cmd}/{arg}") as resp:
                        if resp.status == 200:
                            try:
                                # Some API responses might lack correct JSON mimetype but contain valid JSON
                                data = await resp.json(content_type=None)
                            except Exception as json_err:
                                text = await resp.text()
                                snippet = text[:200].replace('\n', ' ')
                                content_type = resp.headers.get("Content-Type", "unknown")
                                results[result_key]["details"].append({
                                    "name": "Decode Error",
                                    "status": "FAIL",
                                    "info": f"Expected JSON but got {content_type}. Snippet: {snippet}..."
                                })
                                return

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
    
                            results[result_key]["passed"] = monitor_passed
                        else:
                            results[result_key]["details"].append({
                                "name": "API Error",
                                "status": "FAIL",
                                "info": f"MxToolbox returned status {resp.status}"
                            })
                 except Exception as e:
                     results[result_key]["details"].append({
                         "name": "Scan Error",
                         "status": "FAIL",
                         "info": str(e)
                     })

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

    # Note: Headers are per-request, so we'll just track the last one's headers for quotas
    return results

async def query_mxtoolbox_with_headers(domain: str, dkim_selector: str = None) -> tuple[dict, dict]:
    """
    Wrapper that also returns headers for quota tracking.
    """
    if not settings.mx_key or not domain:
        return {}, {}

    base_url = "https://api.mxtoolbox.com/api/v1/lookup"
    headers = {
        "Authorization": settings.mx_key,
        "Accept": "application/json"
    }
    
    results = {
        "mx": {"passed": False, "details": []},
        "blacklist": {"passed": False, "details": []},
        "spf": {"passed": False, "details": []},
        "dkim": {"passed": False, "details": [], "checked": False},
        "dmarc": {"passed": False, "details": []}
    }
    
    last_headers = {}

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async def run_check(cmd, arg, result_key):
                 nonlocal last_headers
                 try:
                     async with session.get(f"{base_url}/{cmd}/{arg}") as resp:
                        last_headers = dict(resp.headers)
                        if resp.status == 200:
                            data = await resp.json(content_type=None)
                            monitor_passed = True
                            for item in data.get("Failed", []):
                                monitor_passed = False
                                results[result_key]["details"].append({
                                    "name": item.get("Name", "Error"),
                                    "status": "FAIL",
                                    "info": item.get("Description", "")
                                })
                            for item in data.get("Passed", []):
                                results[result_key]["details"].append({
                                    "name": item.get("Name", "Info"),
                                    "status": "PASS",
                                    "info": item.get("Description") or item.get("Information", "")
                                })
                            for item in data.get("Information", []):
                                 results[result_key]["details"].append({
                                    "name": item.get("Name", "Info"),
                                    "status": "INFO",
                                    "info": item.get("Description") or item.get("Information", "")
                                })
                            results[result_key]["passed"] = monitor_passed
                 except Exception: pass

            await run_check("mx", domain, "mx")
            await run_check("blacklist", domain, "blacklist")
            if dkim_selector:
                await run_check("dkim", f"{domain}:{dkim_selector}", "dkim")

    except Exception as e:
        results["error"] = str(e)

    return results, last_headers
