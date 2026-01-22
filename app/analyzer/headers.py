import re
import email.utils
from datetime import datetime

def parse_hops(headers: dict) -> list[dict]:
    """
    Parses 'Received' headers to trace the email path and calculate delays.
    """
    hops = []
    # In a dictionary of headers from parsing, 'Received' might be a list or a single string
    # Our msg_parser / eml_parser needs to ensure lists are handled. 
    # Current parsers might flatten headers. 
    # For this implementation, we assume headers['Received'] is accessible.
    
    # Note: Traditional python email parser handles multiple headers by presenting them as a list if asked,
    # but clean dict logic often overwrites. 
    # We will need to assume the caller passes the raw headers dict where keys map to lists if duplicates exist,
    # OR we access the raw_headers list if available.
    # For now, let's implement the logic assuming we can iterate over a list of Received headers.
    
    # Since our current parsers (eml/msg) might return a simple dict, we might need to adjust them to pass
    # a list of all headers or a MultiDict.
    # We will come back to this. For now, we implement the parsing logic.
    
    return hops

def parse_auth_results(headers: dict) -> dict:
    """
    Extracts SPF, DKIM, DMARC status from Authentication-Results headers.
    """
    results = {
        "spf": {"status": "none", "details": "-"},
        "dkim": {"status": "none", "details": "-"},
        "dmarc": {"status": "none", "details": "-"}
    }
    
    # Combine multiple Auth-Res headers
    auth_header = headers.get("Authentication-Results", "")
    if isinstance(auth_header, list):
        auth_header = " ".join(auth_header)
        
    if not auth_header:
        return results
        
    lower_header = auth_header.lower()
    
    # Helper regex
    def extract_status(mech):
        match = re.search(f"{mech}=([a-z]+)", lower_header)
        return match.group(1) if match else "none"
        
    results["spf"]["status"] = extract_status("spf")
    results["dkim"]["status"] = extract_status("dkim")
    results["dmarc"]["status"] = extract_status("dmarc")
    
    # Basic detail extraction (grabbing the whole substring for context)
    # This is a simplification; a full parser would tokenize.
    results["spf"]["details"] = auth_header # Context
    
    return results

def analyze_headers(headers: dict, raw_headers_list: list = None) -> tuple[int, list[str], str | None, list[dict], dict]:
    """
    Analyzes email headers.
    Returns: (score, reasons, dkim_selector, hops, auth_results)
    """
    score = 0
    reasons = []

    # 1. Auth Results
    auth_results = parse_auth_results(headers)
    
    if auth_results["spf"]["status"] in ["fail", "softfail"]:
        score += 20
        reasons.append("SPF Validation Failed")
    
    if auth_results["dkim"]["status"] == "fail":
        score += 20
        reasons.append("DKIM Validation Failed")
        
    if auth_results["dmarc"]["status"] == "fail":
        score += 30
        reasons.append("DMARC Validation Failed")

    # Extract DKIM Selector
    dkim_selector = None
    dkim_header = headers.get("DKIM-Signature", "")
    if isinstance(dkim_header, list): dkim_header = dkim_header[0] # Take first
    
    if dkim_header:
        match = re.search(r's=([^;]+)', dkim_header)
        if match:
            dkim_selector = match.group(1).strip()

    # 2. Urgency
    subject = headers.get("Subject", "")
    if isinstance(subject, list): subject = subject[0]
    subject = subject.lower() if subject else ""
    
    urgency_keywords = ["urgent", "immediate", "action required", "suspended", "verify", "expiry", "expire"]
    for word in urgency_keywords:
        if word in subject:
            score += 10
            reasons.append(f"Urgency keyword '{word}' detected in subject")
            break

    # 3. MX Validation (Simulated)
    sender = headers.get("From", "")
    if isinstance(sender, list): sender = sender[0]
    
    if sender:
        import dns.resolver
        try:
            start = sender.find("@")
            end = sender.find(">")
            if end == -1: end = len(sender)
            domain = sender[start+1:end].strip()
            
            try:
                dns.resolver.resolve(domain, 'MX')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                score += 25
                reasons.append(f"MX lookup failed for '{domain}'")
        except Exception:
            pass
            
    # 4. Hop Parsing
    # We need the list of Received headers. 
    # If raw_headers_list is provided, use it. Otherwise try headers.get("Received")
    hops = []
    received = []
    if raw_headers_list:
        received = [v for k, v in raw_headers_list if k.lower() == "received"]
    elif "Received" in headers:
        val = headers["Received"]
        received = val if isinstance(val, list) else [val]
        
    # Reverse order (Earliest to Latest usually bottom up in file, but email.parser order depends)
    # Typically headers[0] is the top-most (latest). We want Hop 1 to be the bottom-most.
    # So we reverse the list.
    received.reverse()
    
    last_time = None
    for i, r in enumerate(received):
        # Parse timestamp (last part usually)
        # "from ... by ... ; timestamp"
        parts = r.rsplit(';', 1)
        timestamp_str = parts[-1].strip() if len(parts) > 1 else ""
        
        delay = 0
        current_time = None
        
        try:
            # Parse Date
            if timestamp_str:
                current_time = email.utils.parsedate_to_datetime(timestamp_str)
                if last_time:
                    delta = current_time - last_time
                    delay = max(0, int(delta.total_seconds()))
                last_time = current_time
        except Exception:
            pass # Date parse fail
            
        hops.append({
            "hop": i + 1,
            "from": r.split()[1] if len(r.split()) > 1 else "unknown", # Simple extract
            "by": "...", # Parsing "by" is complex regex
            "time": timestamp_str,
            "delay": f"{delay}s" if i > 0 else "*"
        })


    return score, reasons, dkim_selector, hops, auth_results
