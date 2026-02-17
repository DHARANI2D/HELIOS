import re
import email.utils
import email.parser
from datetime import datetime

def parse_headers_from_text(text: str) -> tuple[dict, list]:
    """
    Parses raw header text into a dict and a list of tuples.
    """
    msg = email.parser.Parser().parsestr(text)
    headers_dict = dict(msg.items())
    headers_list = list(msg.items())
    return headers_dict, headers_list

def parse_auth_results(headers: dict) -> dict:
    """
    Extracts detailed SPF, DKIM, DMARC status and policies from Authentication-Results.
    """
    results = {
        "spf": {"status": "none", "details": "-"},
        "dkim": {"status": "none", "details": "-"},
        "dmarc": {"status": "none", "details": "-"},
        "tls": {"version": "Unknown", "cipher": "Unknown"}
    }
    
    # Combined Auth-Results
    auth_header = headers.get("Authentication-Results", "")
    if isinstance(auth_header, list): auth_header = " ".join(auth_header)
    
    if auth_header:
        auth_lower = auth_header.lower()
        # Extract statuses
        spf_match = re.search(r'spf=([a-z]+)', auth_lower)
        dkim_match = re.search(r'dkim=([a-z]+)', auth_lower)
        dmarc_match = re.search(r'dmarc=([a-z]+)', auth_lower)
        
        results["spf"]["status"] = spf_match.group(1) if spf_match else "none"
        results["dkim"]["status"] = dkim_match.group(1) if dkim_match else "none"
        results["dmarc"]["status"] = dmarc_match.group(1) if dmarc_match else "none"
        
        # Policy & Alignment
        if "p=" in auth_lower:
            policy_match = re.search(r'\(p=([a-z]+)\)', auth_lower)
            if policy_match: results["dmarc"]["details"] = f"Policy: {policy_match.group(1)}"
            
    return results

def extract_tls_info(received_headers: list) -> dict:
    """Extracts TLS version and cipher from Received headers."""
    for r in received_headers:
        tls = re.search(r'version=(TLS[\d\.]+)', r, re.I)
        cipher = re.search(r'cipher=([A-Z0-9_\-]+)', r, re.I)
        if tls:
            return {
                "version": tls.group(1),
                "cipher": cipher.group(1) if cipher else "Unknown"
            }
    return {"version": "Unknown", "cipher": "Unknown"}

def analyze_headers(headers: dict, raw_headers_list: list = None) -> tuple[int, list[str], str | None, list[dict], dict]:
    """
    Professional Header Analysis.
    Returns: (score, reasons, dkim_selector, hops, auth_results)
    """
    score = 0
    reasons = []
    
    raw_list = raw_headers_list or []
    received = [v for k, v in raw_list if k.lower() == "received"]
    if not received and "Received" in headers:
        val = headers["Received"]
        received = val if isinstance(val, list) else [val]
    
    # 1. Auth Results & TLS
    auth_results = parse_auth_results(headers)
    tls_info = extract_tls_info(received)
    auth_results["tls"] = tls_info

    if auth_results["spf"]["status"] in ["fail", "softfail"]:
        score += 25
        reasons.append(f"SPF Validation Failed ({auth_results['spf']['status']})")
    
    if auth_results["dkim"]["status"] == "fail":
        score += 25
        reasons.append("DKIM Validation Failed - Message integrity compromised")
        
    if auth_results["dmarc"]["status"] == "fail":
        score += 40
        reasons.append("DMARC Validation Failed - Domain Spoofing likely")

    # 2. DKIM Signature Deep Scan
    dkim_selector = None
    dkim_sig = headers.get("DKIM-Signature", "")
    if isinstance(dkim_sig, list): dkim_sig = dkim_sig[0]
    if dkim_sig:
        d_match = re.search(r'd=([^;]+)', dkim_sig)
        s_match = re.search(r's=([^;]+)', dkim_sig)
        if s_match: dkim_selector = s_match.group(1).strip()
        auth_results["dkim"]["details"] = f"Domain: {d_match.group(1) if d_match else 'Unknown'}, Selector: {dkim_selector}"

    # 3. Urgency & Suspicious Patterns
    subject = str(headers.get("Subject", "")).lower()
    urgency_keywords = ["urgent", "immediate", "action required", "suspended", "verify", "expiry", "expire"]
    for word in urgency_keywords:
        if word in subject:
            score += 15
            reasons.append(f"High Urgency Subject: '{word}' detected")
            break

    # 4. Hop/IP Path Trace
    hops = []
    received_working = list(received)
    received_working.reverse() # Bottom-up Trace
    
    last_time = None
    for i, r in enumerate(received_working):
        parts = r.rsplit(';', 1)
        timestamp_str = parts[-1].strip() if len(parts) > 1 else ""
        
        delay = 0
        current_time = None
        try:
            if timestamp_str:
                current_time = email.utils.parsedate_to_datetime(timestamp_str)
                if last_time and current_time:
                    delta = current_time - last_time
                    delay = max(0, int(delta.total_seconds()))
                last_time = current_time
        except: pass
            
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', r)
        if not ip_match: ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', r)
        hop_ip = ip_match.group(1) if ip_match else "unknown"

        hops.append({
            "hop": i + 1,
            "from": r.split()[1] if len(r.split()) > 1 else "unknown",
            "ip": hop_ip,
            "time": timestamp_str,
            "delay": f"{delay}s" if i > 0 else "*"
        })

    # 5. DMARC DNS Check (if domain found)
    sender = str(headers.get("From", ""))
    if "@" in sender:
        try:
            domain = sender.split("@")[-1].split(">")[0].strip()
            import dns.resolver
            try:
                txt_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
                for rdata in txt_records:
                    if "v=DMARC1" in str(rdata):
                        auth_results["dmarc"]["details"] += f" | DNS: {str(rdata)[:50]}..."
            except: pass
        except: pass

    return score, reasons, dkim_selector, hops, auth_results
