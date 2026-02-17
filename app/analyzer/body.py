import re
import tldextract
import aiohttp
from app.core.config import settings
from datetime import datetime
from app.analyzer.utils import decode_proofpoint_url
from app.analyzer.html_intelligence import analyze_html_intelligence

async def check_url_intel(url: str, is_domain: bool = True) -> tuple[int, str | None, int | None, dict | None, dict]:
    """
    Checks URL or Domain intelligence via VirusTotal.
    Returns: (score_penalty, warning_message, age_days, intel_dict, headers)
    """
    if not settings.vt_key:
        return 0, None, None, None, {}
    
    import urllib.parse
    if is_domain:
        endpoint = f"https://www.virustotal.com/api/v3/domains/{url}"
    else:
        # For URLs, VT requires SHA256 of the URL
        import hashlib
        url_id = hashlib.sha256(url.encode()).hexdigest()
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
    headers = {"x-apikey": settings.vt_key}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(endpoint, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    
                    stats = attrs.get("last_analysis_stats", {})
                    malicious_hits = stats.get("malicious", 0)
                    
                    intel = {
                        "registrar": attrs.get("registrar", "Unknown"),
                        "reputation": attrs.get("reputation", 0),
                        "hits": malicious_hits,
                        "stats": stats,
                        "type": "domain" if is_domain else "url",
                        "categories": list(attrs.get("categories", {}).values()),
                        "tags": attrs.get("tags", []),
                        "last_analysis": attrs.get("last_analysis_date")
                    }

                    age_days = None
                    creation_date = attrs.get("creation_date") or attrs.get("first_submission_date")
                    if creation_date:
                        created = datetime.fromtimestamp(creation_date)
                        age_days = (datetime.now() - created).days
                        intel["age"] = age_days
                        
                    if malicious_hits > 0:
                        return 50 + (malicious_hits * 5), f"VT: {url} has {malicious_hits} malicious detections.", age_days, intel, dict(resp.headers)
                    
                    if is_domain and age_days and age_days < 365:
                        return 75, f"Domain '{url}' is young ({age_days} days).", age_days, intel, dict(resp.headers)
                        
                    return 0, None, age_days, intel, dict(resp.headers)
    except Exception:
        pass
        
    return 0, None, None, None, {}

async def check_domain_age(domain: str) -> tuple[int, str | None, int | None, dict | None, dict]:
    return await check_url_intel(domain, is_domain=True)

def analyze_body(text: str, whitelist: list[str] = None, session_dir: str = None) -> tuple[int, list[str], list[str], list[str]]:
    """
    Analyzes body text/html for NLP keywords, extracts URLs, and inspects domains.
    Accepts optional session_dir to scan specific body-*.txt files for accurate URL extraction.
    Returns: (score, reasons, extracted_urls, suspicious_domains, whitelisted_hits, html_intel)
    """
    """
    Analyzes body text/html for NLP keywords, extracts URLs, and inspects domains.
    Returns: (score, reasons, extracted_urls, suspicious_domains, whitelisted_hits, html_intel)
    """
    score = 0
    reasons = []
    suspicious_domains = []
    
    # 0. HTML Intelligence (If content looks like HTML)
    html_intel = {}
    if "<html" in text.lower() or "<body" in text.lower() or "<script" in text.lower() or "<form" in text.lower():
        html_intel = analyze_html_intelligence(text)
        if html_intel["score"] > 0:
            score += html_intel["score"]
            reasons.extend(html_intel["reasons"])
            for indicator in html_intel["js_indicators"]:
                reasons.append(f"Security Alert (JS): {indicator}")

    text_lower = text.lower()
    
    # 1. Credential Harvesting Intent
    cred_keywords = ["password", "credential", "login", "sign in", "verify your account", "access suspended"]
    hit_count = 0
    for word in cred_keywords:
        if word in text_lower:
            hit_count += 1
    
    if hit_count >= 2:
        score += 15
        reasons.append("Content suggests credential harvesting intent (login/password keywords)")

    # 2. Financial/Lure Intent
    lure_keywords = ["invoice", "payment", "overdue", "receipt", "winning", "lottery"]
    for word in lure_keywords:
        if word in text_lower:
            score += 5
            reasons.append(f"Financial/Lure keyword '{word}' detected")
            break

    # 3. URL Extraction (Updated to use robust user-defined logic)
    from app.analyzer.url_extractor import extract_urls_from_text, extract_urls_recursive
    import os
    
    urls = []
    
    # Priority: Scan ALL files in session directory if available (User Requirement)
    if session_dir and os.path.exists(session_dir):
        urls = extract_urls_recursive(session_dir)
    
    # Fallback to scanning the provided text if no files found or no session
    if not urls:
        urls = extract_urls_from_text(text)
    
    # Urls are already deduped and cleaned by the extractor
    
    # 4. Domain Analysis
    suspicious_tlds = ["cc", "xyz", "top", "download", "review", "country", "stream"]
    high_value_keywords = ["microsoft", "google", "apple", "paypal", "secure", "login", "account"]

    # Redundant decoding block removed - handled by url_extractor
    final_urls = urls 
    
    # Whitelist Logic - FILTER FIRST
    effective_whitelist = whitelist if whitelist is not None else settings.DOMAIN_WHITELIST
    whitelisted_hits = []
    
    # Filtered lists
    clean_urls = []
    suspicious_domains = []

    for url in final_urls:
        try:
            ext = tldextract.extract(url)
            domain = f"{ext.domain}.{ext.suffix}".lower()
            
            # Check Whitelist
            is_whitelisted = False
            for wd in effective_whitelist:
                wd_lower = wd.lower().strip()
                if domain == wd_lower or domain.endswith("." + wd_lower):
                    is_whitelisted = True
                    break
            
            if is_whitelisted:
                whitelisted_hits.append(domain)
                continue # STRICT SKIP: Do not analyze, do not add to suspicious
            
            # If not whitelisted, keep for analysis
            clean_urls.append(url)
            
            # TLD Check
            if ext.suffix in suspicious_tlds:
                score += 10
                reasons.append(f"Suspicious TLD '.{ext.suffix}' detected in domain {domain}")
                suspicious_domains.append(domain)

            # Keyword Check
            for kw in high_value_keywords:
                if kw in ext.domain and domain not in ["microsoft.com", "google.com", "apple.com", "paypal.com"]:
                    score += 15
                    reasons.append(f"High-value keyword '{kw}' found in suspicious domain {domain}")
                    suspicious_domains.append(domain)

        except Exception:
            continue
    
    # 5. TOAD
    phone_pattern = re.compile(r'(?:\+?1[-. ]?)?\(?([2-9][0-8][0-9])\)?[-. ]?([2-9][0-9]{2})[-. ]?([0-9]{4})')
    phones = phone_pattern.findall(text)
    if phones:
        if "call" in text_lower or "support" in text_lower or "helpline" in text_lower:
            score += 10
            reasons.append("Potential TOAD indicator: Phone numbers detected with support keywords")

    # Clean up lists
    whitelisted_hits = list(set(whitelisted_hits))
    suspicious_domains = list(set(suspicious_domains))
    clean_urls = list(set(clean_urls))

    return score, reasons, clean_urls, suspicious_domains, whitelisted_hits, html_intel
