import asyncio
from playwright.async_api import async_playwright
import tldextract
from app.core.schemas import SandboxResult, NetworkRequest
from app.sandbox.exfiltration import ExfiltrationEngine

class Sandbox:
    async def analyze_url(self, url: str) -> SandboxResult:
        import hashlib
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        
        async with async_playwright() as p:
            # Launch headless chromium
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            )
            page = await context.new_page()

            network_logs = []
            redirect_chain = []
            screenshot_chain = []
            dom_mutations = []
            detected_forms = []
            exfiltrated = None
            js_analysis = []

            import time
            import uuid
            
            run_id = f"{int(time.time())}_{uuid.uuid4().hex[:6]}"
            screenshot_rel_path = f"sandbox_{url_hash}_{run_id}_final.png"
            final_url = url

            async def capture_screenshot(u, label=""):
                try:
                    idx = len(screenshot_chain)
                    # Unique filename for every hop
                    path = f"hop_{url_hash}_{run_id}_{idx}.png"
                    await page.screenshot(path=f"app/static/{path}")
                    screenshot_chain.append({"url": u, "path": path, "label": label or f"Hop {idx}"})
                except Exception: pass

            # --- Intermediate Screenshots ---
            async def on_frame_navigated(frame):
                if frame == page.main_frame:
                    await capture_screenshot(frame.url, label="Navigation")

            page.on("framenavigated", on_frame_navigated)

            # Dummy Credentials
            DUMMY_EMAIL = "forensic-test@example.com"
            DUMMY_PASSWORD = "Password123!"

            # --- Network Listener (SOC-Grade Exfiltration Detection) ---
            exfil_engine = ExfiltrationEngine()
            exfiltration_report = {
                "pillar_1": {"detected": False, "summary": "No sensitive data found in payloads", "details": []},
                "pillar_2": {"detected": False, "summary": "All requests sent to authorized destinations", "details": []},
                "pillar_3": {"detected": False, "summary": "No stealthy/automated exfiltration patterns detected", "details": []},
                "pii_detected": [],
                "dns_tunneling": False,
                "entropy": 0.0,
                "obfuscation_layers": 0
            }

            def on_request(request):
                nonlocal exfiltrated
                try:
                    from urllib.parse import unquote
                    import base64
                    
                    req_url = request.url
                    ext = tldextract.extract(req_url)
                    domain = f"{ext.domain}.{ext.suffix}"
                    
                    network_logs.append(NetworkRequest(
                        url=req_url, 
                        method=request.method, 
                        domain=domain
                    ))
                    
                    # Core Exfiltration Check (Triggered on POST/PUT or XHR/Fetch)
                    resource_type = request.resource_type
                    is_suspicious_method = request.method in ["POST", "PUT", "PATCH"]
                    is_background_req = resource_type in ["xhr", "fetch", "ping", "websocket"]
                    
                    if is_suspicious_method or is_background_req:
                        post_data = unquote(request.post_data or "")
                        
                        # --- Deep Forensic Inspection via ExfiltrationEngine ---
                        exfil_res = exfil_engine.process_payload(post_data, ext.subdomain, domain)
                        
                        # Update Report Metadata
                        if exfil_res["pii_detected"]:
                            exfiltration_report["pii_detected"].extend(exfil_res["pii_detected"])
                            exfiltration_report["pillar_1"]["detected"] = True
                            exfiltration_report["pillar_1"]["summary"] = f"Sensitive data detected: {', '.join(set(exfil_res['pii_detected']))}"
                            exfiltration_report["pillar_1"]["details"].append(f"Found {exfil_res['pii_detected']} in {request.method} to {domain}")

                        if exfil_res["dns_tunneling"]:
                            exfiltration_report["dns_tunneling"] = True
                            exfiltration_report["pillar_2"]["detected"] = True
                            exfiltration_report["pillar_2"]["summary"] = "High-confidence DNS Tunneling detected"
                            exfiltration_report["pillar_2"]["details"].extend(exfil_res["dns_reasons"])

                        exfiltration_report["entropy"] = max(exfiltration_report["entropy"], exfil_res["entropy"])
                        exfiltration_report["obfuscation_layers"] = max(exfiltration_report["obfuscation_layers"], exfil_res["obfuscation_layers"])

                        # Pillar 2: Unauthorized Destination (Standard check)
                        origin_ext = tldextract.extract(url)
                        origin_domain = f"{origin_ext.domain}.{origin_ext.suffix}"
                        if domain != origin_domain and domain not in ["google.com", "gstatic.com", "googleapis.com", "microsoft.com", "bing.com"]:
                            exfiltration_report["pillar_2"]["detected"] = True
                            if not exfiltration_report["dns_tunneling"]:
                                exfiltration_report["pillar_2"]["summary"] = f"Data sent to external/unauthorized domain: {domain}"
                            exfiltration_report["pillar_2"]["details"].append(f"Request to {domain} deviates from landing origin {origin_domain}")

                        # Pillar 3: Stealth Behavior (Standard check + Engine signals)
                        stealth_indicators = []
                        if is_background_req: stealth_indicators.append("Background Beacon (XHR/Fetch)")
                        if exfil_res["obfuscation_layers"] > 1:
                            stealth_indicators.append(f"Nested Obfuscation ({exfil_res['obfuscation_layers']} layers: {', '.join(exfil_res['obfuscation_signals'])})")
                        if exfil_res["entropy"] > 4.5:
                            stealth_indicators.append(f"High-Entropy Payload ({exfil_res['entropy']:.2f})")
                        
                        if stealth_indicators:
                            exfiltration_report["pillar_3"]["detected"] = True
                            exfiltration_report["pillar_3"]["summary"] = f"Stealthy patterns: {', '.join(stealth_indicators)}"
                            exfiltration_report["pillar_3"]["details"].append(f"Method: {request.method}, Type: {resource_type}")

                        # Update overall detection if all pillars or critical combination found
                        if exfiltration_report["pillar_1"]["detected"] or exfiltration_report["pillar_2"]["detected"]:
                            exfiltrated = {
                                "verdict": "Confirmed" if all(exfiltration_report[p]["detected"] for p in ["pillar_1", "pillar_2", "pillar_3"]) else "Suspicious",
                                "pillars": exfiltration_report,
                                "target_url": req_url,
                                "method": request.method
                            }
                except Exception:
                    pass

            page.on("request", on_request)

            try:
                # --- Navigation ---
                wait_until = "domcontentloaded" if url.startswith("data:") else "networkidle"
                response = await page.goto(url, timeout=45000, wait_until=wait_until)
                
                # Capture initial/landing
                await capture_screenshot(page.url, label="Landing")
                
                # Give it a second to settle and for scripts to run
                await asyncio.sleep(2) 
                
                if response:
                    req_ptr = response.request
                    while req_ptr.redirected_from:
                        redirect_chain.insert(0, req_ptr.redirected_from.url)
                        req_ptr = req_ptr.redirected_from
                    redirect_chain.append(response.url)
                
                final_url = page.url
                
                # Final settle and capture
                if final_url != url:
                    await capture_screenshot(final_url, label="Final")

                # --- Script Analysis --- (omitted for brevity in replacement, but I must keep it)
                # ... [same script analysis as before]
                scripts = await page.evaluate("""() => {
                    const found = [];
                    document.querySelectorAll('script').forEach(s => {
                        found.push({
                            src: s.src || 'inline',
                            type: s.type,
                            content_preview: s.src ? '' : s.innerText.substring(0, 100).replace(/\\n/g, ' ')
                        });
                    });
                    return found;
                }""")
                for s in scripts:
                    flags = []
                    if s["src"] == 'inline':
                        if "eval(" in s["content_preview"]: flags.append("Uses eval()")
                        if "document.write" in s["content_preview"]: flags.append("Uses document.write")
                    js_analysis.append({"script": s["src"], "flags": flags, "preview": s["content_preview"]})

                # --- Form Detection ---
                forms = await page.query_selector_all('form')
                for i, form in enumerate(forms):
                    f_info = {
                        "id": await form.get_attribute("id") or f"form_{i}",
                        "action": await form.get_attribute("action") or final_url,
                        "fields": []
                    }
                    inputs = await form.query_selector_all('input')
                    email_field = None
                    pass_field = None
                    for inp in inputs:
                        itype = await inp.get_attribute("type") or "text"
                        iname = await inp.get_attribute("name") or await inp.get_attribute("id") or "unknown"
                        f_info["fields"].append({"type": itype, "name": iname})
                        if not email_field and (itype in ["email", "text"] and any(k in iname.lower() for k in ["email", "user", "login"])):
                            email_field = inp
                        if not pass_field and itype == "password":
                            pass_field = inp
                    detected_forms.append(f_info)
                    if email_field or pass_field:
                        dom_mutations.append(f"interacted_with_form_{i}")
                        if email_field: await email_field.fill(DUMMY_EMAIL)
                        if pass_field: await pass_field.fill(DUMMY_PASSWORD)
                        await asyncio.sleep(1)
                        submit_btn = await form.query_selector('button[type="submit"], input[type="submit"]')
                        if submit_btn: await submit_btn.click()
                        else: await form.evaluate("form => form.submit()")
                        await asyncio.sleep(3)
                        await capture_screenshot(page.url, label="Post-Submit")

                # Final Screenshot
                await page.screenshot(path=f"app/static/{screenshot_rel_path}")

            except Exception as e:
                dom_mutations.append(f"error_during_execution: {str(e)}")
                # Attempt to capture state even on error
                try:
                    await page.screenshot(path=f"app/static/{screenshot_rel_path}")
                    screenshot_chain.append({"url": page.url, "path": screenshot_rel_path, "label": "Error State"})
                except Exception:
                    pass
            
            # Ensure final screenshot exists if not created yet
            import os
            if not os.path.exists(f"app/static/{screenshot_rel_path}"):
                 try:
                    await page.screenshot(path=f"app/static/{screenshot_rel_path}")
                 except: pass

            await browser.close()
            
            return SandboxResult(
                url=url,
                expanded_url=final_url,
                redirect_chain=redirect_chain,
                screenshot_path=screenshot_rel_path,
                screenshot_chain=screenshot_chain,
                network_requests=network_logs,
                dom_mutations=dom_mutations,
                detected_forms=detected_forms,
                exfiltration_detected=exfiltrated,
                js_analysis=js_analysis
            )

    async def screenshot_html(self, html: str, path: str):
        """
        Renders HTML in a browser and captures a screenshot.
        """
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(viewport={'width': 800, 'height': 600})
            page = await context.new_page()
            
            # Encapsulate in basic styles to ensure it looks like an email
            styled_html = f"""
            <html>
                <head>
                    <style>
                        body {{ font-family: sans-serif; padding: 20px; line-height: 1.5; color: #333; }}
                        pre {{ white-space: pre-wrap; word-wrap: break-word; }}
                    </style>
                </head>
                <body>{html}</body>
            </html>
            """
            await page.set_content(styled_html)
            await page.screenshot(path=path)
            await browser.close()
