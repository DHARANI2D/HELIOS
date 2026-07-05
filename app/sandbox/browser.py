import asyncio
import json
import logging
import os
import shutil
import threading
import time
import uuid
import tldextract
from concurrent.futures import ThreadPoolExecutor

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from webdriver_manager.chrome import ChromeDriverManager

from app.core.schemas import SandboxResult, NetworkRequest
from app.sandbox.exfiltration import ExfiltrationEngine

logger = logging.getLogger("uvicorn")


_DUMMY_FIRST_NAMES = ["jsmith", "mwilson", "achen", "rpatel", "kbrown", "tnguyen", "lgarcia", "dokafor"]
# RFC 2606 reserved domains: guaranteed non-existent/non-deliverable, so a
# randomized local part can never accidentally reach a real mailbox.
_DUMMY_EMAIL_DOMAINS = ["example.com", "example.org", "example.net"]


def _generate_dummy_credentials() -> tuple[str, str]:
    """
    Generates a fresh, obviously-fake but non-static test identity for each
    sandbox run. A fixed literal (e.g. always 'forensic-test@example.com')
    is exactly the kind of thing a phishing kit operator could hardcode a
    filter against to silently swallow DESAS's credential-harvesting probes;
    varying it per run keeps the automated probe indistinguishable from what
    a human analyst would type ad hoc.
    """
    import random
    import string
    local = random.choice(_DUMMY_FIRST_NAMES) + str(random.randint(100, 999))
    domain = random.choice(_DUMMY_EMAIL_DOMAINS)
    email = f"{local}@{domain}"
    password = (
        "".join(random.choices(string.ascii_uppercase, k=1))
        + "".join(random.choices(string.ascii_lowercase, k=5))
        + str(random.randint(10, 99))
        + random.choice("!@#$")
    )
    return email, password


def _default_worker_count() -> int:
    """
    A human analyst can only open one link at a time; DESAS can parallelize
    detonations across a small pool instead. Sized to the VM's CPU count
    (each headless Chrome instance is its own process/RAM footprint), capped
    at 2 by default since most analyst VMs are modest (2-4 vCPU). Override
    with the SANDBOX_MAX_WORKERS env var for larger VMs.
    """
    override = os.environ.get("SANDBOX_MAX_WORKERS")
    if override:
        try:
            return max(1, int(override))
        except ValueError:
            pass
    return max(1, min(2, os.cpu_count() or 1))


class Sandbox:
    def __init__(self):
        self._executor = ThreadPoolExecutor(max_workers=_default_worker_count())
        self._driver_path = None
        self._driver_path_lock = threading.Lock()

    def _get_driver_path(self) -> str:
        """
        Resolves the ChromeDriver path once and reuses it for every run, instead
        of hitting webdriver-manager's version-check/download on every single
        detonation. This matters more on an analyst VM than it would on a always-on
        server: it removes a live network dependency from the hot path (each
        detonation no longer needs to phone home to resolve a driver) and avoids
        every concurrent worker independently racing to download the same file.
        Thread-safe so the small worker pool (see _default_worker_count) can share it.
        """
        if self._driver_path and os.path.exists(self._driver_path):
            return self._driver_path
        with self._driver_path_lock:
            if not self._driver_path or not os.path.exists(self._driver_path):
                self._driver_path = ChromeDriverManager().install()
                logger.info(f"Resolved ChromeDriver: {self._driver_path}")
        return self._driver_path

    async def analyze_url(self, url: str) -> SandboxResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._analyze_sync, url)

    def _analyze_sync(self, url: str) -> SandboxResult:
        import hashlib
        import tempfile
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        run_id = f"{int(time.time())}_{uuid.uuid4().hex[:6]}"
        screenshot_rel_path = f"sandbox_{url_hash}_{run_id}_final.png"

        driver = None
        profile_dir = tempfile.mkdtemp(prefix=f"desas_chrome_{run_id}_")
        try:
            # Setup Chrome Options
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--ignore-certificate-errors")
            # Explicit throwaway profile per run: guarantees this automated session
            # never touches the analyst's own Chrome profile/cookies/history on the
            # same VM, and that concurrent runs (see ThreadPoolExecutor pool) don't
            # collide on the same profile directory.
            chrome_options.add_argument(f"--user-data-dir={profile_dir}")

            # Enable Performance Logging for CDP
            chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})

            # Initialize Driver
            service = Service(self._get_driver_path())
            driver = webdriver.Chrome(service=service, options=chrome_options)

            # Helper for screenshots
            screenshot_chain = []
            
            def capture_screenshot(u, label=""):
                try:
                    idx = len(screenshot_chain)
                    path = f"hop_{url_hash}_{run_id}_{idx}.png"
                    full_path = os.path.join("app", "static", path)
                    driver.save_screenshot(full_path)
                    screenshot_chain.append({"url": u, "path": path, "label": label or f"Hop {idx}"})
                except Exception: pass

            # Initialize Exfiltration Engine
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
            exfiltrated = None

            # Ensure URL has protocol
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            # Navigate
            driver.get(url)
            time.sleep(2) # Wait for initial load
            capture_screenshot(driver.current_url, label="Landing")
            
            # Wait for some network idle-ish state or just fixed delay
            time.sleep(3)

            final_url = driver.current_url
            if final_url != url:
                capture_screenshot(final_url, label="Final")

            # --- Network Analysis (CDP via Performance Logs) ---
            network_logs = []
            document_chains = {}  # requestId -> ordered list of URLs for top-level navigations
            logs = driver.get_log("performance")

            for entry in logs:
                try:
                    message_obj = json.loads(entry["message"])
                    message = message_obj.get("message", {})
                    method = message.get("method")

                    if method == "Network.requestWillBeSent":
                        params = message.get("params", {})
                        request = params.get("request", {})
                        req_url = request.get("url")
                        req_method = request.get("method")
                        post_data = request.get("postData", "")
                        res_type = params.get("type", "Unknown")
                        request_id = params.get("requestId")

                        if not req_url: continue

                        ext = tldextract.extract(req_url)
                        domain = f"{ext.domain}.{ext.suffix}"

                        network_logs.append(NetworkRequest(
                            url=req_url,
                            method=req_method,
                            domain=domain
                        ))

                        # Track the real hop-by-hop chain for the top-level document navigation.
                        # CDP emits one Network.requestWillBeSent per hop for the same requestId,
                        # each carrying the URL it redirected *to* (redirectResponse holds the prior hop).
                        if res_type == "Document" and request_id:
                            chain = document_chains.setdefault(request_id, [])
                            if not chain or chain[-1] != req_url:
                                chain.append(req_url)

                        # Exfiltration Checks
                        is_suspicious_method = req_method in ["POST", "PUT", "PATCH"]
                        # We can't easily distinguish XHR/Fetch from resource type in simple logs sometimes, 
                        # but we can assume mostly XHR for dynamic stuff or check 'type' if available in params
                        # 'type': 'XHR', 'Fetch', etc. exist in params usually
                        res_type = params.get("type", "Unknown").lower()
                        is_background_req = res_type in ["xhr", "fetch", "ping", "websocket"]

                        if is_suspicious_method or is_background_req:
                            from urllib.parse import unquote
                            decoded_post = unquote(post_data or "")
                            
                            exfil_res = exfil_engine.process_payload(decoded_post, ext.subdomain, domain)
                            
                            if exfil_res["pii_detected"]:
                                exfiltration_report["pii_detected"].extend(exfil_res["pii_detected"])
                                exfiltration_report["pillar_1"]["detected"] = True
                                exfiltration_report["pillar_1"]["summary"] = f"Sensitive data detected: {', '.join(set(exfil_res['pii_detected']))}"
                                exfiltration_report["pillar_1"]["details"].append(f"Found {exfil_res['pii_detected']} in {req_method} to {domain}")

                            if exfil_res["dns_tunneling"]:
                                exfiltration_report["dns_tunneling"] = True
                                exfiltration_report["pillar_2"]["detected"] = True
                                exfiltration_report["pillar_2"]["summary"] = "High-confidence DNS Tunneling detected"
                                exfiltration_report["pillar_2"]["details"].extend(exfil_res["dns_reasons"])

                            exfiltration_report["entropy"] = max(exfiltration_report["entropy"], exfil_res["entropy"])
                            exfiltration_report["obfuscation_layers"] = max(exfiltration_report["obfuscation_layers"], exfil_res["obfuscation_layers"])

                            origin_ext = tldextract.extract(final_url)
                            origin_domain = f"{origin_ext.domain}.{origin_ext.suffix}"
                            
                            if domain != origin_domain and domain not in ["google.com", "gstatic.com", "googleapis.com", "microsoft.com", "bing.com"]:
                                exfiltration_report["pillar_2"]["detected"] = True
                                if not exfiltration_report["dns_tunneling"]:
                                    exfiltration_report["pillar_2"]["summary"] = f"Data sent to external/unauthorized domain: {domain}"
                                exfiltration_report["pillar_2"]["details"].append(f"Request to {domain} deviates from landing origin {origin_domain}")

                            stealth_indicators = []
                            if is_background_req: stealth_indicators.append("Background Beacon (XHR/Fetch)")
                            if exfil_res["obfuscation_layers"] > 1:
                                stealth_indicators.append(f"Nested Obfuscation ({exfil_res['obfuscation_layers']} layers)")
                            if exfil_res["entropy"] > 4.5:
                                stealth_indicators.append(f"High-Entropy Payload ({exfil_res['entropy']:.2f})")
                            
                            if stealth_indicators:
                                exfiltration_report["pillar_3"]["detected"] = True
                                exfiltration_report["pillar_3"]["summary"] = f"Stealthy patterns: {', '.join(stealth_indicators)}"
                                exfiltration_report["pillar_3"]["details"].append(f"Method: {req_method}, Type: {res_type}")

                            if exfiltration_report["pillar_1"]["detected"] or exfiltration_report["pillar_2"]["detected"]:
                                exfiltrated = {
                                    "verdict": "Confirmed" if all(exfiltration_report[p]["detected"] for p in ["pillar_1", "pillar_2", "pillar_3"]) else "Suspicious",
                                    "pillars": exfiltration_report,
                                    "target_url": req_url,
                                    "method": req_method
                                }

                except Exception: pass

            # Resolve the real redirect chain: pick the document-navigation chain whose
            # first hop matches the URL we actually navigated to, falling back to the
            # simplified [url, final_url] pair if CDP didn't give us anything usable.
            redirect_chain = [url]
            for chain in document_chains.values():
                if chain and chain[0].rstrip('/') == url.rstrip('/'):
                    redirect_chain = chain
                    break
            if redirect_chain[-1].rstrip('/') != final_url.rstrip('/'):
                redirect_chain.append(final_url)

            # --- DOM / JS Analysis ---
            js_analysis = []
            try:
                scripts = driver.execute_script("""
                    const found = [];
                    document.querySelectorAll('script').forEach(s => {
                        found.push({
                            src: s.src || 'inline',
                            type: s.type,
                            content_preview: s.src ? '' : s.innerText.substring(0, 100).replace(/\\n/g, ' ')
                        });
                    });
                    return found;
                """)
                for s in scripts:
                    flags = []
                    if s["src"] == 'inline':
                        if "eval(" in s["content_preview"]: flags.append("Uses eval()")
                        if "document.write" in s["content_preview"]: flags.append("Uses document.write")
                    js_analysis.append({"script": s["src"], "flags": flags, "preview": s["content_preview"]})
            except Exception: pass

            # --- Form Interaction ---
            detected_forms = []
            dom_mutations = []
            DUMMY_EMAIL, DUMMY_PASSWORD = _generate_dummy_credentials()

            try:
                forms = driver.find_elements(By.TAG_NAME, "form")
                for i, form in enumerate(forms):
                    try:
                        f_info = {
                            "id": form.get_attribute("id") or f"form_{i}",
                            "action": form.get_attribute("action") or final_url,
                            "fields": []
                        }
                        
                        inputs = form.find_elements(By.TAG_NAME, "input")
                        email_field = None
                        pass_field = None
                        
                        for inp in inputs:
                            itype = inp.get_attribute("type") or "text"
                            iname = inp.get_attribute("name") or inp.get_attribute("id") or "unknown"
                            f_info["fields"].append({"type": itype, "name": iname})
                            
                            if not email_field and (itype in ["email", "text"] and any(k in iname.lower() for k in ["email", "user", "login"])):
                                email_field = inp
                            if not pass_field and itype == "password":
                                pass_field = inp
                        
                        detected_forms.append(f_info)

                        if email_field or pass_field:
                            dom_mutations.append(f"interacted_with_form_{i}")
                            if email_field: email_field.send_keys(DUMMY_EMAIL)
                            if pass_field: pass_field.send_keys(DUMMY_PASSWORD)
                            time.sleep(1)
                            
                            # Try submit
                            try:
                                submit_btn = form.find_element(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
                                submit_btn.click()
                            except:
                                driver.execute_script("arguments[0].submit();", form)
                            
                            time.sleep(3)
                            capture_screenshot(driver.current_url, label="Post-Submit")

                    except Exception as e:
                        logger.warning(f"Form interaction failed: {e}")
            except Exception: pass

            # Final Screenshot
            driver.save_screenshot(os.path.join("app", "static", screenshot_rel_path))

            interacted = any(m.startswith("interacted_with_form") for m in dom_mutations)

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
                js_analysis=js_analysis,
                test_credentials_used={"email": DUMMY_EMAIL} if interacted else None
            )

        except Exception as e:
            logger.error(f"Selenium Sandbox Failed: {e}")
            return SandboxResult(
                url=url,
                expanded_url=url,
                redirect_chain=[],
                screenshot_path="",
                screenshot_chain=[],
                network_requests=[],
                dom_mutations=[f"CRITICAL_ERROR: {str(e)}"],
                detected_forms=[],
                exfiltration_detected=None,
                js_analysis=[]
            )
        finally:
            if driver:
                driver.quit()
            shutil.rmtree(profile_dir, ignore_errors=True)

    async def screenshot_html(self, html: str, path: str):
        """
        Renders HTML in a browser and captures a screenshot using Selenium.
        """
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._screenshot_html_sync, html, path)

    def _screenshot_html_sync(self, html: str, path: str):
        import tempfile
        driver = None
        temp_file = None
        profile_dir = tempfile.mkdtemp(prefix="desas_chrome_shot_")
        try:
             # Setup Chrome Options
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=800,600")
            chrome_options.add_argument(f"--user-data-dir={profile_dir}")

            # Initialize Driver
            service = Service(self._get_driver_path())
            driver = webdriver.Chrome(service=service, options=chrome_options)

            # Create temp HTML file
            fd, temp_path = tempfile.mkstemp(suffix=".html", text=True)
            with os.fdopen(fd, 'w') as f:
                f.write(html)

            driver.get(f"file://{temp_path}")
            driver.save_screenshot(path)

            temp_file = temp_path

        except Exception as e:
            logger.error(f"Screenshot HTML failed: {e}")
        finally:
            if driver:
                driver.quit()
            shutil.rmtree(profile_dir, ignore_errors=True)
            if temp_file and os.path.exists(temp_file):
                os.remove(temp_file)
