import asyncio
from playwright.async_api import async_playwright
import tldextract
from app.core.schemas import SandboxResult, NetworkRequest

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
            screenshot_rel_path = f"static/sandbox_{url_hash}.png"
            final_url = url

            async def capture_screenshot(u, label=""):
                try:
                    idx = len(screenshot_chain)
                    path = f"static/hop_{url_hash}_{idx}.png"
                    await page.screenshot(path=f"app/{path}")
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

            # --- Network Listener ---
            def on_request(request):
                nonlocal exfiltrated
                try:
                    from urllib.parse import unquote
                    ext = tldextract.extract(request.url)
                    domain = f"{ext.domain}.{ext.suffix}"
                    network_logs.append(NetworkRequest(
                        url=request.url, 
                        method=request.method, 
                        domain=domain
                    ))
                    
                    # Exfiltration Check
                    if request.method == "POST":
                        post_data = unquote(request.post_data or "")
                        if DUMMY_EMAIL in post_data:
                            exfiltrated = {
                                "target_url": request.url,
                                "method": request.method,
                                "data_found": DUMMY_EMAIL,
                                "type": "Credential Exfiltration"
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
                await page.screenshot(path=f"app/{screenshot_rel_path}")

            except Exception as e:
                dom_mutations.append(f"error_during_execution: {str(e)}")
            
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
