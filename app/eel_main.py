import eel
import os
import sys
import io

# GUI Patch: Redirect stdout/stderr to dummy streams if None (Windows --noconsole fix)
if sys.stdout is None:
    sys.stdout = io.StringIO()
if sys.stderr is None:
    sys.stderr = io.StringIO()
import uuid
import tempfile
import base64
import logging
import tldextract
import asyncio
import webbrowser
import zipfile
import io
from pydantic import BaseModel

# Modular Analyzers
from app.analyzer.eml_parser import parse_eml
from app.analyzer.msg_parser import parse_msg
from app.analyzer.headers import analyze_headers, parse_headers_from_text
from app.analyzer.body import analyze_body, check_url_intel
from app.analyzer.attachments import analyze_attachments
from app.analyzer.reputation import get_ip_intel
from app.analyzer.mxtoolbox import query_mxtoolbox_with_headers
from app.analyzer.report_generator import generate_html_report
from app.sandbox.browser import Sandbox
from app.core.scoring import aggregate_verdict, calculate_sandbox_score
from app.core.schemas import AnalysisResult, SandboxResult
from app.core.config import settings
from app.core.whitelist_manager import (
    get_whitelist, add_to_whitelist, remove_from_whitelist,
    export_whitelist_to_excel, import_whitelist_from_excel
)
from app.core.settings_manager import save_settings, get_dynamic_settings, AppSettings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("eel-backend")

sandbox = Sandbox()

# --- Eel Exposed Functions ---

@eel.expose
def get_app_settings():
    """Returns the current application settings."""
    try:
        return get_dynamic_settings().model_dump()
    except Exception as e:
        logger.error(f"Error getting settings: {e}")
        return {}

@eel.expose
def update_app_settings(new_settings):
    """Updates and saves the application settings."""
    try:
        success = save_settings(new_settings)
        return {"status": "success" if success else "error"}
    except Exception as e:
        logger.error(f"Error saving settings: {e}")
        return {"status": "error", "message": str(e)}

@eel.expose
def get_domain_whitelist():
    """Returns the current domain whitelist."""
    try:
        return get_whitelist()
    except Exception as e:
        logger.error(f"Error getting whitelist: {e}")
        return []

@eel.expose
def add_domain_to_whitelist(domain):
    """Adds a domain to the whitelist."""
    updated_list = add_to_whitelist(domain)
    return {"status": "success", "whitelist": updated_list}

@eel.expose
def remove_domain_from_whitelist(domain):
    """Removes a domain from the whitelist."""
    updated_list = remove_from_whitelist(domain)
    return {"status": "success", "whitelist": updated_list}

@eel.expose
def download_forensic_report(data):
    """Generates an HTML report and returns it as a base64 string."""
    try:
        html_content = generate_html_report(data)
        b64_content = base64.b64encode(html_content.encode('utf-8')).decode('utf-8')
        return {"status": "success", "content": b64_content}
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return {"status": "error", "message": str(e)}

@eel.expose
def export_whitelist_xl():
    """Exports whitelist to an Excel file and returns it as base64."""
    try:
        temp_fd, temp_path = tempfile.mkstemp(suffix=".xlsx")
        os.close(temp_fd)
        export_whitelist_to_excel(temp_path)
        
        with open(temp_path, "rb") as f:
            b64_content = base64.b64encode(f.read()).decode('utf-8')
        os.remove(temp_path)
        return {"status": "success", "content": b64_content, "filename": "whitelist.xlsx"}
    except Exception as e:
        logger.error(f"Error exporting whitelist: {e}")
        return {"status": "error", "message": str(e)}

@eel.expose
def bundle_forensic_case(data):
    """Creates a ZIP containing the HTML report and all sandbox screenshots."""
    try:
        # 1. Generate HTML Report
        html_content = generate_html_report(data)
        
        # 2. Setup ZIP in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            # Add Report
            zip_file.writestr("Forensic_Report.html", html_content)
            
            # Add Screenshots
            screenshots_dir = "Screenshots"
            
            # Primary body screenshot if exists
            if data.get("primary_body_screenshot"):
                s_path = os.path.join("app", "static", data["primary_body_screenshot"])
                if os.path.exists(s_path):
                    zip_file.write(s_path, f"{screenshots_dir}/Email_Body.png")
            
            # Sandbox results
            sandbox_results = data.get("sandbox_results", [])
            for i, res in enumerate(sandbox_results):
                # Final screenshot
                if res.get("screenshot_path"):
                    s_path = os.path.join("app", "static", res["screenshot_path"])
                    if os.path.exists(s_path):
                        zip_file.write(s_path, f"{screenshots_dir}/Sandbox_{i}_Final.png")
                
                # Screenshot chain (hops)
                chain = res.get("screenshot_chain", [])
                for j, hop in enumerate(chain):
                    if hop.get("path"):
                        h_path = os.path.join("app", "static", hop["path"])
                        if os.path.exists(h_path):
                            label = hop.get("label", f"Hop_{j}").replace(" ", "_")
                            zip_file.write(h_path, f"{screenshots_dir}/Sandbox_{i}_{label}_{j}.png")

        zip_buffer.seek(0)
        b64_content = base64.b64encode(zip_buffer.getvalue()).decode('utf-8')
        filename = f"DESAS_Case_{data.get('subject', 'Untitled').replace(' ', '_')}.zip"
        
        return {"status": "success", "content": b64_content, "filename": filename}
    except Exception as e:
        logger.error(f"Error bundling case: {e}")
        return {"status": "error", "message": str(e)}

@eel.expose
def open_external_url(url):
    """Opens a URL in the default system browser."""
    try:
        webbrowser.open(url)
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error opening URL {url}: {e}")
        return {"status": "error", "message": str(e)}
        
        os.remove(temp_path)
        return {"status": "success", "content": b64_content, "filename": "desas_whitelist_export.xlsx"}
    except Exception as e:
        logger.error(f"Error exporting whitelist: {e}")
        return {"status": "error", "message": str(e)}

@eel.expose
def import_whitelist_xl(file_content_base64):
    """Imports whitelist from a base64 encoded Excel file."""
    try:
        content = base64.b64decode(file_content_base64)
        temp_fd, temp_path = tempfile.mkstemp(suffix=".xlsx")
        os.close(temp_fd)
        
        with open(temp_path, "wb") as f:
            f.write(content)
            
        updated_list = import_whitelist_from_excel(temp_path)
        os.remove(temp_path)
        return {"status": "success", "whitelist": updated_list}
    except Exception as e:
        logger.error(f"Error importing whitelist: {e}")
        return {"status": "error", "message": str(e)}

@eel.expose
def inspect_email_file(file_name, file_content_base64):
    """
    Parses an email and returns a list of its components/attachments for interactive selection.
    Expects file_content_base64 as a base64 encoded string.
    """
    try:
        content = base64.b64decode(file_content_base64)
        session_id = str(uuid.uuid4())
        temp_root = os.path.join(tempfile.gettempdir(), "desas_sessions")
        temp_dir = os.path.join(temp_root, session_id)
        os.makedirs(temp_dir, exist_ok=True)
        
        file_path = os.path.join(temp_dir, file_name)
        with open(file_path, "wb") as f:
            f.write(content)
            
        logger.info(f"Session {session_id}: Saved upload to {file_path}")
        
        attachments_list = []
        
        if file_name.lower().endswith('.msg'):
            from app.analyzer.msg_parser import extract_attachments_to_dir
            extract_attachments_to_dir(file_path, temp_dir)
        else:
            parsed = parse_eml(content)
            for i, att in enumerate(parsed.get("attachments", [])):
                aname = att.get("filename", f"attachment_{i}.bin")
                apath = os.path.join(temp_dir, aname)
                with open(apath, "wb") as af:
                    af.write(att.get("content", b""))
        
        all_files = os.listdir(temp_dir)
        all_files = [f for f in all_files if f != file_name]
        
        for f in all_files:
            attachments_list.append({
                "filename": f,
                "size": os.path.getsize(os.path.join(temp_dir, f)),
                "content_type": "application/octet-stream"
            })
            
        return {
            "session_id": session_id,
            "filename": file_name,
            "attachments": attachments_list
        }
    except Exception as e:
        logger.error(f"Error inspecting email: {e}")
        return {"error": str(e)}

@eel.expose
def analyze_email_eel(file_name, file_content_base64, options):
    """
    Main analysis function for Eel.
    `options` includes: analysis_mode, target_attachment, header_attachment, session_id.
    """
    # Wrap async logic to be reachable from sync Eel
    return asyncio.run(_analyze_email_logic(file_name, file_content_base64, options))

async def _analyze_email_logic(file_name, file_content_base64, options):
    try:
        analysis_mode = options.get("analysis_mode", "direct")
        target_attachment = options.get("target_attachment")
        header_attachment = options.get("header_attachment")
        session_id = options.get("session_id")
        
        parsed_data = None
        content = None
        
        # 1. Load Content
        if session_id and analysis_mode in ["attachment", "forensic"]:
            temp_root = os.path.join(tempfile.gettempdir(), "desas_sessions")
            temp_dir = os.path.join(temp_root, session_id)
            if not os.path.exists(temp_dir):
                return {"error": "Session expired or invalid"}
                
            if not target_attachment:
                 return {"error": "Target attachment required"}
                 
            target_path = os.path.join(temp_dir, target_attachment)
            if not os.path.exists(target_path):
                 return {"error": f"Target file {target_attachment} not found"}
            
            with open(target_path, "rb") as f:
                content = f.read()
            
            fname_lower = target_attachment.lower()
            if fname_lower.endswith('.msg'):
                parsed_data = parse_msg(content)
            else:
                parsed_data = parse_eml(content)
                
            # SPECIAL: Body Reference Override
            all_files = os.listdir(temp_dir)
            body_ref_file = next((f for f in all_files if f.startswith("body-") and f.endswith(".txt")), None)
            if body_ref_file:
                b_path = os.path.join(temp_dir, body_ref_file)
                try:
                    with open(b_path, "r", encoding="utf-8", errors="ignore") as bf:
                        parsed_data["primary_body"] = bf.read()
                except Exception as e:
                    logger.warning(f"Failed to read body ref file: {e}")

            # SPECIAL: Header Override
            if header_attachment:
                 h_path = os.path.join(temp_dir, header_attachment)
                 if os.path.exists(h_path):
                     try:
                         with open(h_path, "r", encoding="utf-8", errors="ignore") as hf:
                             h_dict, h_raw = parse_headers_from_text(hf.read())
                             if h_dict:
                                 parsed_data["headers"] = h_dict
                                 parsed_data["raw_headers"] = h_raw
                     except Exception as e:
                         logger.warning(f"Failed to load header file: {e}")
        else:
            # Direct Mode
            content = base64.b64decode(file_content_base64)
            if file_name.lower().endswith('.msg'):
                parsed_data = parse_msg(content)
            else:
                parsed_data = parse_eml(content)

        if not parsed_data:
            return {"error": "Failed to parse email content"}

        # 2. Build Result
        result = AnalysisResult(
            subject=parsed_data.get("subject", "Unknown"),
            sender=parsed_data.get("from", "Unknown"),
            recipient=parsed_data.get("to", "Unknown"),
            date=parsed_data.get("headers", {}).get("Date", "Unknown"),
            url="",
            expanded_url="",
            redirect_chain=[],
            network_requests=[],
            dom_mutations=[],
            suspicious_domains=[]
        )

        target_headers = parsed_data.get("headers", {})
        target_raw_headers = parsed_data.get("raw_headers", [])
        target_body = parsed_data.get("primary_body", "")
        target_body_html = parsed_data.get("primary_body_html", "")
        target_attachments = parsed_data.get("attachments", [])

        if analysis_mode != "attachment":
            for att in parsed_data.get("attachments", []):
                fname = att.get("filename", "").lower()
                if "headers" in fname and fname.endswith(".txt"):
                    try:
                        header_text = att.get("content", b"").decode("utf-8", errors="ignore")
                        h_dict, h_raw = parse_headers_from_text(header_text)
                        if h_dict:
                            target_headers, target_raw_headers = h_dict, h_raw
                    except: pass
                if "body" in fname and (fname.endswith(".html") or fname.endswith(".txt")):
                    try:
                        b_content = att.get("content", b"").decode("utf-8", errors="ignore")
                        if b_content.strip().startswith("<") or "<html" in b_content.lower():
                            target_body_html = b_content
                    except: pass

        parsed_data["headers"] = target_headers
        parsed_data["raw_headers"] = target_raw_headers
        parsed_data["primary_body"] = target_body
        parsed_data["primary_body_html"] = target_body_html
        parsed_data["attachments"] = target_attachments
        result.primary_body_html = target_body_html or target_body

        # 3. Header Analysis
        logger.info(f"Session {session_id}: Starting header analysis")
        h_score, h_reasons, dkim_selector, hops, auth_results = analyze_headers(parsed_data["headers"], parsed_data.get("raw_headers"))
        result.header_score = h_score
        result.header_reasons = h_reasons
        result.hops = hops
        result.auth_results = auth_results
        result.all_headers = [{"name": k, "value": str(v)} for k, v in parsed_data.get("raw_headers", [])]
        logger.info(f"Session {session_id}: Header analysis complete. Score adjustment: {h_score}")

        # 4. Body Analysis
        logger.info(f"Session {session_id}: Starting body analysis")
        dynamic_whitelist = get_whitelist()
        session_scan_dir = None
        if session_id and analysis_mode == "attachment":
             temp_root = os.path.join(tempfile.gettempdir(), "desas_sessions")
             session_scan_dir = os.path.join(temp_root, session_id)

        b_score, b_reasons, urls, susp_domains, skipped_whitelist, html_intel = analyze_body(
            target_body + " " + target_body_html, 
            whitelist=dynamic_whitelist,
            session_dir=session_scan_dir
        )
        logger.info(f"Session {session_id}: Body analysis complete. Extracted {len(urls)} URLs")

        for url in urls:
            is_dom = False
            try:
                ext = tldextract.extract(url)
                if not ext.suffix: is_dom = True 
            except: pass
            
            logger.info(f"Session {session_id}: Checking intel for {url}")
            d_score, d_reason, d_age, d_intel, vt_h = await check_url_intel(url, is_domain=is_dom)
            if d_intel:
                result.url_intel[url] = d_intel
                if d_age is not None: result.domain_age_days[url] = d_age
            if d_score > 0:
                b_score += d_score
                b_reasons.append(d_reason)
        logger.info(f"Session {session_id}: URL intel check complete")

        result.body_score = b_score
        result.body_reasons = b_reasons
        result.suspicious_domains = susp_domains
        result.whitelisted_domains = skipped_whitelist
        result.extracted_urls = urls
        result.html_analysis = html_intel

        # 5. MxToolbox
        sender_email = parsed_data.get("from", "")
        if sender_email:
            start = sender_email.find("@")
            end = sender_email.find(">")
            if end == -1: end = len(sender_email)
            sender_domain = sender_email[start+1:end].strip()
            mx_result, _ = await query_mxtoolbox_with_headers(sender_domain, dkim_selector)
            result.mxtoolbox_analysis = mx_result
            if mx_result.get("blacklist", {}).get("passed") is False:
                 result.header_score += 50
                 result.header_reasons.append(f"MxToolbox: Domain {sender_domain} is on BLACKLIST")

        # 6. Attachments
        filtered_attachments = [att for att in parsed_data.get("attachments", []) 
                               if not (att.get("filename", "").lower() in ["headers.txt", "body.txt", "body.html"])]
        if filtered_attachments:
            logger.info(f"Session {session_id}: Starting analysis of {len(filtered_attachments)} attachments")
            a_score, a_reasons, processed_attachments, att_domains = await analyze_attachments(filtered_attachments)
            result.body_score += a_score
            result.body_reasons.extend(a_reasons)
            result.attachments = processed_attachments
            if att_domains:
                # Add unique domains to suspicious_domains list
                current_domains = set(result.suspicious_domains)
                current_domains.update(att_domains)
                result.suspicious_domains = list(current_domains)
                
                # Check intel for these new domains so they appear in the report
                for domain in att_domains:
                    if domain not in result.url_intel:
                         d_score, d_reason, d_age, d_intel, _ = await check_url_intel(domain, is_domain=True)
                         if d_intel:
                             result.url_intel[domain] = d_intel
                         if d_age is not None:
                             result.domain_age_days[domain] = d_age
            logger.info(f"Session {session_id}: Attachment analysis complete")

        # 7. IP Intel
        unique_ips = {h["ip"] for h in hops if h["ip"] != "unknown"}
        for ip in unique_ips:
            intel = await get_ip_intel(ip)
            result.ip_intel[ip] = intel
            if intel.get("abuse_score", 0) >= 50:
                result.header_score += 20
                result.header_reasons.append(f"Network Intel: Infrastructure IP {ip} flagged")

        # 8. Verdict
        logger.info(f"Session {session_id}: Aggregating final verdict")
        final_result = aggregate_verdict(result)
        logger.info(f"Session {session_id}: Analysis complete. Verdict: {final_result.verdict}")
        return final_result.model_dump()

    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return {"error": str(e)}

@eel.expose
def analyze_standalone_eel(type, input_data):
    """Handles forensic toolkit standalone requests."""
    return asyncio.run(_analyze_standalone_logic(type, input_data))

async def _analyze_standalone_logic(type, input_data):
    try:
        if type == 'header':
            h_dict, h_list = parse_headers_from_text(input_data)
            h_score, h_reasons, dkim_selector, hops, auth_results = analyze_headers(h_dict, h_list)
            ip_intel = {h["ip"]: await get_ip_intel(h["ip"]) for h in hops if h["ip"] != "unknown"}
            return {
                "score": h_score, "reasons": h_reasons, "hops": hops,
                "auth_results": auth_results, "ip_intel": ip_intel,
                "all_headers": [{"name": k, "value": str(v)} for k, v in h_list]
            }
        elif type == 'url':
            raw_sb_result = await sandbox.analyze_url(input_data)
            score, reasons, _ = calculate_sandbox_score(raw_sb_result)
            raw_sb_result.score = score
            raw_sb_result.reasons = reasons
            raw_sb_result.status = "complete"
            return raw_sb_result.model_dump()
        elif type == 'domain':
            domain = input_data.lower().strip()
            score, reason, age, intel, _ = await check_url_intel(domain, is_domain=True)
            return {"domain": domain, "score": score, "reason": reason, "age_days": age, "intel": intel}
        elif type == 'ip':
            return await get_ip_intel(input_data)
        elif type == 'attachment':
            content = base64.b64decode(input_data['content'])
            a_score, a_reasons, processed, att_domains = await analyze_attachments([{"filename": input_data['filename'], "content": content}])
            return {
                "score": a_score, 
                "reasons": a_reasons, 
                "attachment": processed[0] if processed else {},
                "extracted_domains": att_domains
            }
    except Exception as e:
        logger.error(f"Standalone tool error: {e}")
        return {"error": str(e)}

# --- Startup Logic ---

@eel.expose
def check_playwright_status():
    """Checks if Playwright browsers are installed. Returns boolean."""
    marker_path = os.path.join(tempfile.gettempdir(), "desas_playwright_installed.marker")
    return os.path.exists(marker_path)

@eel.expose
def install_playwright_browsers():
    """Installs Playwright browsers via subprocess."""
    try:
        import subprocess
        logger.info("Installing Playwright Chromium...")
        creationflags = 0
        if sys.platform == "win32":
            creationflags = 0x08000000 # CREATE_NO_WINDOW
            
        subprocess.check_call(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            creationflags=creationflags
        )
        
        marker_path = os.path.join(tempfile.gettempdir(), "desas_playwright_installed.marker")
        with open(marker_path, "w") as f:
            f.write("installed")
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Playwright install failed: {e}")
        return {"status": "error", "message": str(e)}

def start_app():
    if getattr(sys, 'frozen', False):
        web_folder = os.path.join(sys._MEIPASS, 'app', 'static')
        if not os.path.exists(web_folder):
             web_folder = os.path.join(sys._MEIPASS, 'static')
    else:
        web_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

    logger.info(f"Starting Eel with web folder: {web_folder}")
    eel.init(web_folder)

    try:
        eel.start('index.html', size=(1200, 900), host='127.0.0.1', port=8675)
    except (SystemExit, KeyboardInterrupt):
        logger.info("Application closed.")

if __name__ == '__main__':
    start_app()
