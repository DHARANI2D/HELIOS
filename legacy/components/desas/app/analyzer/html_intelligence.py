import re
import bs4
from bs4 import BeautifulSoup
import logging
import tldextract
from app.analyzer.utils import decode_proofpoint_url

logger = logging.getLogger("uvicorn")

class HTMLScanner:
    def __init__(self):
        # 1. Obfuscation indicators
        self.js_obfuscation_patterns = [
            (r'eval\(', "Use of 'eval()' detected (potential obfuscation)"),
            (r'String\.fromCharCode', "Use of 'String.fromCharCode' detected (potential obfuscation)"),
            (r'atob\(', "Use of 'atob()' detected (Base64 decoding)"),
            (r'unescape\(', "Use of 'unescape()' detected"),
            (r'\\x[0-9a-fA-F]{2}', "Hex-encoded character escapes detected")
        ]

        # 2. Sensitive API access
        self.js_sensitive_patterns = [
            (r'document\.cookie', "Script accessing browser cookies"),
            (r'localStorage', "Script accessing local storage"),
            (r'sessionStorage', "Script accessing session storage"),
            (r'location\.href\s*=', "Script attempting to redirect the page")
        ]

        # 3. Data exfiltration field names (common targets)
        self.sensitive_field_names = [
            "password", "passwd", "pwd", "ssn", "socialsecurity", 
            "creditcard", "ccnum", "cvv", "cvc", "pin", "otp", "secret"
        ]

    def scan_html(self, html_content: str) -> dict:
        """
        Scans HTML/JS for malicious indicators and data exfiltration patterns.
        """
        results = {
            "score": 0,
            "reasons": [],
            "forms": [],
            "js_indicators": [],
            "suspicious_elements": []
        }

        if not html_content:
            return results

        soup = BeautifulSoup(html_content, 'html.parser')

        # --- 1. Script Analysis ---
        scripts = soup.find_all('script')
        for script in scripts:
            script_text = script.string or ""
            if script.get('src'):
                # Check external script source
                src = script.get('src')
                # If it's an external relative or suspicious URL
                if "://" in src:
                    ext = tldextract.extract(src)
                    domain = f"{ext.domain}.{ext.suffix}"
                    # Add logic if domain is suspicious
            
            # Check internal script content
            for pattern, msg in self.js_obfuscation_patterns:
                if re.search(pattern, script_text, re.IGNORECASE):
                    results["js_indicators"].append(msg)
                    results["score"] += 10
            
            for pattern, msg in self.js_sensitive_patterns:
                if re.search(pattern, script_text, re.IGNORECASE):
                    results["js_indicators"].append(msg)
                    results["score"] += 5

        # --- 2. Form & Data Exfil Analysis ---
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            
            form_info = {
                "action": action,
                "method": method,
                "fields": [],
                "target_type": "Internal"
            }

            # Check action URL
            if action:
                decoded_action = decode_proofpoint_url(action)
                if "://" in decoded_action:
                    form_info["target_type"] = "External"
                    results["score"] += 15
                    results["reasons"].append(f"Form data is sent to an external URL: {decoded_action}")

            # Check fields
            inputs = form.find_all(['input', 'textarea', 'select'])
            for inp in inputs:
                name = (inp.get('name') or inp.get('id') or "").lower()
                type_ = inp.get('type', 'text').lower()
                
                field_data = {"name": name, "type": type_}
                form_info["fields"].append(field_data)

                # Check for sensitive fields being harvested
                for target in self.sensitive_field_names:
                    if target in name:
                        results["score"] += 20
                        results["reasons"].append(f"Potential data exfiltration: Form contains sensitive field '{name}' aiming at external target")
                        break

            # Hidden forms/inputs
            if form.get('style') and 'display:none' in form.get('style').replace(' ', ''):
                results["score"] += 10
                results["reasons"].append("Hidden form detected (potential stealthy data harvesting)")

            results["forms"].append(form_info)

        # --- 3. Suspicious HTML Elements ---
        # Meta refresh
        meta_refresh = soup.find('meta', attrs={'http-equiv': 'refresh'})
        if meta_refresh:
            content = meta_refresh.get('content', '')
            if 'url' in content.lower():
                results["score"] += 10
                results["reasons"].append(f"Meta Refresh redirect detected: {content}")

        # Suspicious iframes
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            src = iframe.get('src', '')
            if src:
                results["score"] += 5
                results["reasons"].append(f"External IFrame detected: {src}")

        # Final Dedupe reasons
        results["reasons"] = list(set(results["reasons"]))
        results["js_indicators"] = list(set(results["js_indicators"]))
        
        return results

def analyze_html_intelligence(html: str) -> dict:
    scanner = HTMLScanner()
    return scanner.scan_html(html)
