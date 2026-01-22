import re
import tldextract
import aiohttp
from app.core.config import settings
from datetime import datetime

async def check_domain_age(domain: str) -> tuple[int, str | None]:
    """
    Checks domain age via VirusTotal (if API key present).
    Returns: (score_penalty, warning_message)
    """
    if not settings.VIRUSTOTAL_API_KEY:
        return 0, None
        
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    creation_date = data.get("data", {}).get("attributes", {}).get("creation_date")
                    if creation_date:
                        # VT returns timestamp
                        created = datetime.fromtimestamp(creation_date)
                        age_days = (datetime.now() - created).days
                        
                        if age_days < 365:
                            return 20, f"Domain '{domain}' is young (< 1 year old: {age_days} days)"
    except Exception:
        pass
        
    return 0, None

def analyze_body(text: str) -> tuple[int, list[str], list[str], list[str]]:
    """
    Analyzes body text/html for NLP keywords, extracts URLs, and inspects domains.
    Returns: (score, reasons, extracted_urls, suspicious_domains)
    """
    score = 0
    reasons = []
    suspicious_domains = []

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

    # 3. URL Extraction
    # Robust regex for http/https
    url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:[^\s<>"\'()]+)?')
    urls = list(set(url_pattern.findall(text))) # Dedupe

    # 4. Domain Analysis
    suspicious_tlds = ["cc", "xyz", "top", "download", "review", "country", "stream"]
    high_value_keywords = ["microsoft", "google", "apple", "paypal", "secure", "login", "account"]

    for url in urls:
        try:
            ext = tldextract.extract(url)
            domain = f"{ext.domain}.{ext.suffix}"
            tld = ext.suffix
            
            # Heuristic 1: Suspicious TLD
            if tld in suspicious_tlds:
                score += 10
                reasons.append(f"Suspicious TLD '.{tld}' detected in domain {domain}")
                suspicious_domains.append(domain)

            # Heuristic 2: Brand/Security keywords in non-official domains
            # e.g., "microsoft-secure.com" (simplified check)
            for kw in high_value_keywords:
                if kw in ext.domain and domain not in ["microsoft.com", "google.com", "apple.com", "paypal.com"]:
                    score += 15
                    reasons.append(f"High-value keyword '{kw}' found in suspicious domain {domain}")
                    suspicious_domains.append(domain)

        except Exception:
            continue
    
    # Dedupe domains
    
    # 5. TOAD (Telephone-Oriented Attack Delivery) Detection
    # Regex for common phone formats, looking for "call" keywords nearby would be better but simple regex for now
    # Matches: +1-800-555-0199, (800) 555-0199, 800-555-0199
    phone_pattern = re.compile(r'(?:\+?1[-. ]?)?\(?([2-9][0-8][0-9])\)?[-. ]?([2-9][0-9]{2})[-. ]?([0-9]{4})')
    phones = phone_pattern.findall(text)
    
    if phones:
        # Simple heuristic: presence of phone numbers with "call" or "support"
        if "call" in text_lower or "support" in text_lower or "helpline" in text_lower:
            score += 10
            reasons.append("Potential TOAD indicator: Phone numbers detected with support keywords")

    # 6. Whitelist Filtering
    final_suspicious_domains = []
    whitelisted_hits = []
    
    for d in suspicious_domains:
        is_whitelisted = False
        for wd in settings.DOMAIN_WHITELIST:
            if d.endswith(wd): # simple suffix match for subdomains
                is_whitelisted = True
                break
        
        if is_whitelisted:
            whitelisted_hits.append(d)
        else:
            final_suspicious_domains.append(d)

    return score, reasons, urls, final_suspicious_domains, whitelisted_hits
