import asyncio
from playwright.async_api import async_playwright
import tldextract
from app.core.schemas import AnalysisResult, NetworkRequest

class Sandbox:
    async def analyze_url(self, url: str) -> AnalysisResult:
        async with async_playwright() as p:
            # Launch headless chromium with strict sandboxing
            browser = await p.chromium.launch(headless=True)
            # Create a new context (incognito for each run)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            )
            page = await context.new_page()

            network_logs = []
            redirect_chain = []
            dom_mutations = []
            screenshot_rel_path = None
            final_url = url
            
            # --- Network Listener ---
            def on_request(request):
                try:
                    ext = tldextract.extract(request.url)
                    domain = f"{ext.domain}.{ext.suffix}"
                    network_logs.append(NetworkRequest(
                        url=request.url, 
                        method=request.method, 
                        domain=domain
                    ))
                except Exception:
                    pass

            page.on("request", on_request)

            try:
                # --- Navigate ---
                # We track the initial response to see the chain
                response = await page.goto(url, timeout=30000, wait_until="networkidle")
                
                # Capture redirect chain
                if response:
                    request_chain = await response.request.all_headers() # getting headers mostly, but let's traverse the chain
                    # The response object has a request, which might have redirects.
                    # Traverse the redirect chain backwards
                    req_ptr = response.request
                    while req_ptr.redirected_from:
                        redirect_chain.insert(0, req_ptr.redirected_from.url)
                        req_ptr = req_ptr.redirected_from
                    redirect_chain.append(response.url)
                
                final_url = page.url

                # --- DOM Analysis ---
                # Check for password fields
                password_inputs = await page.query_selector_all('input[type="password"]')
                if password_inputs:
                    dom_mutations.append("password_field_detected")
                
                # Check for generic "login" or "sign in" text in buttons
                # This contributes to the heuristic
                content = await page.content()
                if "login" in content.lower() or "sign in" in content.lower():
                     dom_mutations.append("login_keywords_detected")

                # Take Screenshot
                screenshot_rel_path = "static/screenshot.png" # Overwrites for demo simplicity
                await page.screenshot(path=f"app/{screenshot_rel_path}")

            except Exception as e:
                # If timeout or error, we still return what we have
                final_url = url
                dom_mutations.append(f"error_during_execution: {str(e)}")
            
            await browser.close()
            
            return AnalysisResult(
                url=url,
                expanded_url=final_url,
                redirect_chain=redirect_chain,
                screenshot_path=screenshot_rel_path,
                network_requests=network_logs,
                dom_mutations=dom_mutations
            )
