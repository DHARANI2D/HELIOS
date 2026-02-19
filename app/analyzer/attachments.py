import hashlib
import logging
import zipfile
import olefile
import io
import aiohttp
import re
import tldextract
from pdfminer.high_level import extract_text as pdf_extract_text
from docx import Document
from app.core.config import settings
from app.analyzer.url_extractor import (
    process_raw_urls, 
    extract_urls_from_text, 
    analyze_image_bytes, 
    is_tesseract_available
)
from app.analyzer.forensics import (
    structural_analysis,
    vba_semantic_analysis,
    obfuscation_heuristics,
    shannon_entropy,
    infer_mitre_techniques,
    pdf_forensic_signals,
    analyze_image_forensics,
    detect_polyglots,
    analyze_ole_streams,
    detect_xlm_macros
)
from app.analyzer.body import check_url_intel

logger = logging.getLogger("uvicorn")

async def analyze_attachments(attachments: list[dict]) -> tuple[int, list[str], list[dict], list[str]]:
    """
    Analyzes attachments for suspicious types, hashes, macros, and nested link intelligence.
    Returns: (score, reasons, processed_attachments, collected_domains)
    """
    from app.analyzer.body import check_domain_age # Lazy import to avoid circular dep
    from app.analyzer.archives import ArchiveAnalyzer

    score = 0
    reasons = []
    processed_attachments = []
    
    archive_analyzer = ArchiveAnalyzer()

    # Pre-process: Expand archives
    all_attachments = list(attachments)
    i = 0
    # Use while loop to safely append to list during iteration
    while i < len(all_attachments):
        att = all_attachments[i]
        fname = att.get("filename", "").lower()
        content = att.get("content", b"")
        
        # Check for archive types
        if fname.endswith((".zip", ".7z")) and not att.get("_scanned_archive"):
            try:
                extracted = archive_analyzer.analyze_archive(file_content=content, filename=fname)
                for e in extracted:
                    # Mark as already scanned so we don't re-extract inner archives
                    e["_scanned_archive"] = True
                    # Tag as extracted for UI/Reporting if needed
                    e["filename"] = f"[Extracted] {e['filename']}"
                    all_attachments.append(e)
            except Exception as e:
                logger.warning(f"Archive expansion failed for {fname}: {e}")
        i += 1

    extracted_domains = set()

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

    for att in all_attachments:
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

        # FORENSIC DATA COLLECTOR
        forensic_signals = {
            "has_macros": False,
            "auto_exec": False,
            "obfuscation": False,
            "high_entropy": False,
            "suspicious_calls": [],
            "mitre_techniques": [],
            "structural_anomalies": [],
            "pdf_flags": [],
            "image_flags": [],
            "polyglot": False,
            "xlm_macro": False,
            "ole_anomaly": False,
            "appended_data": False
        }

        # --- 1. Structural Analysis (All Files) ---
        struct_res = structural_analysis(content, filename)
        if struct_res["structure_score"] > 0:
            score += struct_res["structure_score"]
            reasons.append(f"Structural anomalies in {filename}: {', '.join(struct_res.get('unexpected_files', []))}")
            forensic_signals["structural_anomalies"] = struct_res.get("unexpected_files", [])

        # --- 2. Polyglot & Appended Payload Check ---
        polyglot_findings = detect_polyglots(content)
        if polyglot_findings:
            score += 25
            reasons.extend(polyglot_findings)
            forensic_signals["polyglot"] = True
            if any("Appended" in f for f in polyglot_findings):
                forensic_signals["appended_data"] = True

        # --- Extension Checks ---
        for ext in risky_extensions:
            if filename.endswith(ext):
                score += 20
                risk_label = "High Risk"
                reasons.append(f"Executable attachment detected: {filename}")
                break
        
        # --- Content & Hyperlink Extraction ---
        raw_nested_urls = []
        image_meta = {}
        try:
            if filename.endswith(".pdf"):
                extracted_text = pdf_extract_text(io.BytesIO(content))
                # Deep PDF Forensics
                pdf_res = pdf_forensic_signals(extracted_text, content)
                if pdf_res["has_js"] or pdf_res["has_launch"]:
                    score += 30
                    reasons.append(f"Active content detected in PDF {filename}")
                    forensic_signals["pdf_flags"].append("Active Content (JS/Launch)")
                if pdf_res["evasion_detected"]:
                    score += 20
                    reasons.append(f"PDF evasion techniques detected in {filename}")
                # Extract URLs from PDF text
                nested_urls.extend(extract_urls_from_text(extracted_text))

            elif filename.endswith(".docx") or filename.endswith(".docm"):
                doc = Document(io.BytesIO(content))
                extracted_text = "\n".join([p.text for p in doc.paragraphs])
                for rel in doc.part.rels.values():
                    if "hyperlink" in rel.reltype:
                        raw_nested_urls.append(rel._target)
            elif filename.endswith(".xlsx") or filename.endswith(".xlsm"):
                try:
                    import openpyxl
                    wb = openpyxl.load_workbook(io.BytesIO(content), data_only=True)
                    rows = []
                    for sheet in wb.worksheets:
                        for row in sheet.iter_rows():
                            row_vals = []
                            for cell in row:
                                val = str(cell.value) if cell.value is not None else ""
                                row_vals.append(val)
                                if cell.hyperlink and cell.hyperlink.target:
                                    raw_nested_urls.append(cell.hyperlink.target)
                            
                            if any(v.strip() for v in row_vals):
                                rows.append(" | ".join(row_vals))
                    extracted_text = "\n".join(rows)
                    logger.info(f"Extracted {len(rows)} rows and links from Excel: {filename}")
                    
                    # XLM Macro Check
                    xlm_findings = detect_xlm_macros(extracted_text, content)
                    if xlm_findings:
                        score += 30
                        reasons.extend(xlm_findings)
                        forensic_signals["xlm_macro"] = True
                except Exception as e:
                    logger.warning(f"Excel extraction failed for {filename}: {e}")
            elif filename.endswith(".txt") or filename.endswith(".log"):
                extracted_text = content.decode("utf-8", errors="ignore")
            
            # --- Image Forensic Integration (OCR + Metadata + Entropy) ---
            image_extensions = [".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".webp"]
            if any(filename.endswith(ext) for ext in image_extensions):
                img_urls, ocr_text = analyze_image_bytes(content)
                nested_urls.extend(list(img_urls))
                extracted_text = ocr_text
                
                # Metadata + Entropy Check
                img_forensics = analyze_image_forensics({}, content) # Pass empty exif initially, will rely on byte scan
                if img_forensics["suspicious"]:
                    score += 15
                    reasons.append(f"Suspicious image metadata/entropy in {filename}")
                    forensic_signals["image_flags"].extend(img_forensics["reasons"])
                
                try:
                    from PIL import Image as PILImage
                    with PILImage.open(io.BytesIO(content)) as img:
                        image_meta = {
                            "format": img.format,
                            "size": f"{img.width}x{img.height}",
                            "mode": img.mode,
                            "ocr_active": is_tesseract_available()
                        }
                        # Rescan forensics with actual EXIF
                        exif = img.getexif()
                        if exif:
                            img_forensics_exif = analyze_image_forensics(exif, content)
                            if img_forensics_exif["suspicious"]:
                                score += 15
                                reasons.append(f"Suspicious EXIF data in {filename}")
                                forensic_signals["image_flags"].extend(img_forensics_exif["reasons"])

                except Exception as e:
                    logger.warning(f"Metadata extraction failed for {filename}: {e}")

            # --- Unified Extraction from Text ---
            if extracted_text:
                nested_urls.extend(extract_urls_from_text(extracted_text))
                for pattern in INDICATORS:
                    if re.search(pattern, extracted_text, re.IGNORECASE):
                        # Use a readable label for the phone pattern
                        label = "Phone/Callback Number Pattern" if "\\d" in pattern and "10," in pattern else pattern
                        found_indicators.append(label)
                if found_indicators:
                    score += 15
                    reasons.append(f"Suspicious phishing indicators found in '{filename}': {', '.join(found_indicators[:3])}")
                    if risk_label == "Clean": risk_label = "Suspicious Content"

        except Exception as e:
            logger.error(f"Error analyzing attachment {filename}: {e}")

        # Clean raw gathered URLs (if any from rels)
        if raw_nested_urls:
            nested_urls.extend(process_raw_urls(set(raw_nested_urls)))

        # --- Nested Artifact Intelligence (VT) ---
        nested_urls = list(set(nested_urls))
        nested_intel = {}
        
        for url in nested_urls:
            # Domain Extraction for Inventory
            try:
                ext = tldextract.extract(url)
                if ext.domain and ext.suffix:
                    dom = f"{ext.domain}.{ext.suffix}".lower()
                    extracted_domains.add(dom)
            except: pass

            # Check full URL intel
            u_score, u_reason, u_age, u_intel, _ = await check_url_intel(url, is_domain=False)
            
            # Also extract domain for contextual age check if URL was clean
            domain = ""
            try:
                ext = tldextract.extract(url)
                if ext.domain and ext.suffix:
                    domain = f"{ext.domain}.{ext.suffix}"
            except: pass
            
            nested_intel[url] = {
                "score": u_score,
                "reason": u_reason,
                "age": u_age,
                "intel": u_intel,
                "domain": domain
            }
            
            if u_score > 0:
                score += 15
                reasons.append(f"Nested URL in '{filename}' is malicious: {url}")
                risk_label = "Malicious (Nested Link)"

        has_macros = False
        vba_code_extracted = ""
        
        try:
            # OLE Formats
            if any(filename.endswith(ext) for ext in office_extensions_ole):
                if olefile.isOleFile(io.BytesIO(content)):
                    ole = olefile.OleFileIO(io.BytesIO(content))
                    
                    # Advanced OLE Stream Analysis
                    ole_res = analyze_ole_streams(content)
                    if ole_res["ole_anomalies"]:
                        score += 20
                        reasons.extend(ole_res["risky_streams"])
                        forensic_signals["ole_anomaly"] = True

                    if ole.exists('Macros') or ole.exists('_VBA_PROJECT_CUR') or ole.exists('VBA'):
                        has_macros = True
                        from oletools.olevba import VBA_Parser
                        vba_parser = VBA_Parser(filename, data=content)
                        if vba_parser.detect_vba_macros():
                            forensic_signals["ole_macros"] = []
                            for (subfilename, stream_path, vba_filename, code) in vba_parser.extract_macros():
                                code_sanitized = code.replace('\r', '')
                                vba_code_extracted += code_sanitized + "\n"
                                forensic_signals["ole_macros"].append({
                                    "stream": stream_path,
                                    "filename": vba_filename,
                                    "size": len(code)
                                })
                                # Extract links from macro code
                                macro_urls = extract_urls_from_text(code)
                                nested_urls.extend(macro_urls)
                                if macro_urls:
                                    forensic_signals["suspicious_calls"].append(f"URLs found in macro: {', '.join(macro_urls[:3])}")
            
            # Office XML Formats
            if any(filename.endswith(ext) for ext in office_extensions_xml):
                if zipfile.is_zipfile(io.BytesIO(content)):
                    with zipfile.ZipFile(io.BytesIO(content)) as z:
                        if any(p in z.namelist() for p in ['word/vbaProject.bin', 'xl/vbaProject.bin', 'ppt/vbaProject.bin']):
                            has_macros = True
                            # Extract bin and parse if possible, or just flag
            
            if has_macros:
                score += 30
                risk_label = "High Risk (Macros)"
                reasons.append(f"Macros detected in Office file: {filename}")
                forensic_signals["has_macros"] = True
                
                if any(filename.endswith(ext) for ext in excel_extensions):
                    reasons.append(f"CRITICAL: Active Excel Macros found in {filename} (Potential Dropper)")

                # VSA (VBA Semantic Analysis)
                if vba_code_extracted:
                    vsa_res = vba_semantic_analysis(vba_code_extracted)
                    if vsa_res["auto_exec"]:
                        score += 25
                        reasons.append(f"Auto-execution logic found in macro ({filename})")
                        forensic_signals["auto_exec"] = True
                    if vsa_res["obfuscation"]:
                        score += 20
                        reasons.append(f"Obfuscated macro code detected in {filename}")
                        forensic_signals["obfuscation"] = True
                    if vsa_res["staging_logic"]:
                        score += 20
                        reasons.append(f"Payload staging logic found in macro ({filename})")
                    
                    forensic_signals["suspicious_calls"].extend(vsa_res["suspicious_calls"])
        
        except Exception as e:
            logger.warning(f"Macro analysis error: {e}")

        # --- 5. Obfuscation & Entropy Checks (General) ---
        # Calculate entropy for everything
        e_score = shannon_entropy(content)
        if e_score > 7.2:
            forensic_signals["high_entropy"] = True
            # Only flag if it's not a known compressed format or image
            if not (filename.endswith(".zip") or filename.endswith(".png") or filename.endswith(".jpg")):
                 score += 15
                 reasons.append(f"High entropy content in {filename} (Possible packed payload)")

        # Obfuscation on extracted text (e.g. scripts)
        if extracted_text and any(filename.endswith(ext) for ext in [".js", ".vbs", ".ps1", ".html"]):
             obf_score = obfuscation_heuristics(extracted_text)
             if obf_score > 20:
                 score += obf_score
                 reasons.append(f"Highly obfuscated script detected: {filename}")
                 forensic_signals["obfuscation"] = True

        # --- 6. MITRE Mapping ---
        mitre_hits = infer_mitre_techniques(forensic_signals)
        forensic_signals["mitre_techniques"] = mitre_hits

        
        processed_data = {
            "filename": filename,
            "md5": md5_hash,
            "sha256": sha256_hash,
            "risk": risk_label,
            "vt_stats": None,
            "signature": None,
            "extracted_urls": nested_urls,
            "nested_intel": nested_intel, # Automated link intel
            "indicators": found_indicators,
            "has_macros": has_macros,
            "image_info": image_meta,
            "extracted_text": extracted_text[:2000],
            "forensics": forensic_signals # Deep forensic signals
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
        
    return score, reasons, processed_attachments, list(extracted_domains)
