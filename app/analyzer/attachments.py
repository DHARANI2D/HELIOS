import hashlib
import zipfile
import olefile
import io
import aiohttp
import re
from pypdf import PdfReader
from docx import Document
from app.core.config import settings

import hashlib
import zipfile
import olefile
import io
import aiohttp
import re
import tldextract
from pypdf import PdfReader
from docx import Document
from app.core.config import settings

async def analyze_attachments(attachments: list[dict]) -> tuple[int, list[str], list[dict]]:
    """
    Analyzes attachments for suspicious types, hashes, macros, and nested link intelligence.
    Returns: (score, reasons, processed_attachments)
    """
    from app.analyzer.body import check_domain_age # Lazy import to avoid circular dep

    score = 0
    reasons = []
    processed_attachments = []
    
    risky_extensions = [".exe", ".scr", ".vbs", ".js", ".bat", ".cmd", ".ps1", ".jar"]
    office_extensions_ole = [".doc", ".xls", ".ppt"]
    office_extensions_xml = [".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"]
    excel_extensions = [".xls", ".xlsx", ".xlsm", ".xlsb"]

    # Phishing Indicators (TOAD - Telephone Oriented Attack Delivery)
    INDICATORS = [
        r"callback", r"billing", r"invoice", r"subscription", r"membership",
        r"unauthorized", r"cancel", r"renewal", r"order confirmed", r"pending payment",
        r"\+?[\d\s\-\.\(\)]{10,}" # Generic phone number pattern
    ]

    for att in attachments:
        filename = att.get("filename", "").lower()
        content = att.get("content", b"")
        if content is None: content = b""
        
        # Calculate hashes
        if not isinstance(content, (bytes, bytearray, memoryview)):
            # Attempt to convert if it's a string, otherwise default to empty bytes
            if isinstance(content, str):
                content = content.encode('utf-8')
            else:
                content = b""

        md5_hash = hashlib.md5(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()
        
        risk_label = "Clean"
        extracted_text = ""
        nested_urls = []
        found_indicators = []
        nested_domains_intel = {}

        # --- Extension Checks ---
        for ext in risky_extensions:
            if filename.endswith(ext):
                score += 20
                risk_label = "High Risk"
                reasons.append(f"Executable attachment detected: {filename}")
                break
        
        # --- Content & Hyperlink Extraction ---
        try:
            if filename.endswith(".pdf"):
                reader = PdfReader(io.BytesIO(content))
                for page in reader.pages:
                    # Text Extraction
                    extracted_text += page.extract_text() or ""
                    # Hyperlink/URI Extraction
                    if "/Annots" in page:
                        for annot in page["/Annots"]:
                            obj = annot.get_object()
                            if "/A" in obj and "/URI" in obj["/A"]:
                                nested_urls.append(obj["/A"]["/URI"])

            elif filename.endswith(".docx") or filename.endswith(".docm"):
                doc = Document(io.BytesIO(content))
                # Text Extraction
                extracted_text = "\n".join([p.text for p in doc.paragraphs])
                # Hyperlink Extraction (Rels)
                rels = doc.part.rels
                for rel in rels.values():
                    if "hyperlink" in rel.reltype:
                        nested_urls.append(rel._target)

            elif filename.endswith(".txt") or filename.endswith(".log"):
                extracted_text = content.decode("utf-8", errors="ignore")
            
            # --- Regex Harvesting (as fallback/additional) ---
            if extracted_text:
                links = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', extracted_text)
                nested_urls.extend(links)
                
                # --- TOAD Heuristics ---
                for pattern in INDICATORS:
                    if re.search(pattern, extracted_text, re.IGNORECASE):
                        found_indicators.append(pattern.replace("\\", ""))
                        
                if found_indicators:
                    score += 15
                    reasons.append(f"Suspicious phishing indicators found in '{filename}': {', '.join(found_indicators[:3])}")
                    if risk_label == "Clean": risk_label = "Suspicious Content"

        except Exception:
            pass

        # --- Nested Domain Analytics ---
        nested_urls = list(set(nested_urls))
        unique_domains = set()
        for url in nested_urls:
            try:
                ext = tldextract.extract(url)
                if ext.domain and ext.suffix:
                    domain = f"{ext.domain}.{ext.suffix}"
                    unique_domains.add(domain)
            except Exception:
                continue

        for domain in unique_domains:
            d_score, d_reason, d_age, d_intel = await check_domain_age(domain)
            nested_domains_intel[domain] = {
                "score": d_score,
                "reason": d_reason,
                "age": d_age,
                "intel": d_intel
            }
            if d_score > 0:
                score += 10
                reasons.append(f"Nested link in '{filename}' targets high-risk domain: {domain} ({d_reason})")
                risk_label = "Malicious (Nested Link)"

        # --- Macro Detection ---
        has_macros = False
        try:
            if any(filename.endswith(ext) for ext in office_extensions_ole):
                if olefile.isOleFile(io.BytesIO(content)):
                    ole = olefile.OleFileIO(io.BytesIO(content))
                    if ole.exists('Macros') or ole.exists('_VBA_PROJECT_CUR') or ole.exists('VBA'):
                        has_macros = True
            
            if any(filename.endswith(ext) for ext in office_extensions_xml):
                if zipfile.is_zipfile(io.BytesIO(content)):
                    with zipfile.ZipFile(io.BytesIO(content)) as z:
                        if any(p in z.namelist() for p in ['word/vbaProject.bin', 'xl/vbaProject.bin', 'ppt/vbaProject.bin']):
                            has_macros = True
            
            if has_macros:
                score += 30
                risk_label = "High Risk (Macros)"
                reasons.append(f"Macros detected in Office file: {filename}")
                if any(filename.endswith(ext) for ext in excel_extensions):
                    reasons.append(f"CRITICAL: Active Excel Macros found in {filename} (Potential Dropper)")

        except Exception:
            pass
        
        processed_data = {
            "filename": filename,
            "md5": md5_hash,
            "sha256": sha256_hash,
            "risk": risk_label,
            "vt_stats": None,
            "signature": None,
            "extracted_urls": nested_urls,
            "nested_domains": nested_domains_intel,
            "indicators": found_indicators,
            "has_macros": has_macros
        }

        # --- VirusTotal File Scan ---
        if settings.vt_key:
            try:
                vt_url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
                headers = {"x-apikey": settings.vt_key}
                async with aiohttp.ClientSession() as session:
                    async with session.get(vt_url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            attrs = data.get("data", {}).get("attributes", {})
                            stats = attrs.get("last_analysis_stats", {})
                            if stats:
                                malicious = stats.get("malicious", 0)
                                total = sum(stats.values())
                                processed_data["vt_stats"] = f"{malicious}/{total}"
                                if malicious > 0:
                                    score += (malicious * 5)
                                    reasons.append(f"Attachment '{filename}' flagged by {malicious} vendors in VirusTotal")
                                    processed_data["risk"] = "Malicious (VT)"
                            
                            sig_info = attrs.get("signature_info", {})
                            if sig_info:
                                processed_data["signature"] = {
                                    "product": sig_info.get("product", "Unknown"),
                                    "verified": sig_info.get("verified", "Unknown")
                                }
            except Exception:
                pass

        processed_attachments.append(processed_data)
        
    return score, reasons, processed_attachments
