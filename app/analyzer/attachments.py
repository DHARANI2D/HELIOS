import hashlib
import zipfile
import olefile
import io
import aiohttp
from app.core.config import settings

async def analyze_attachments(attachments: list[dict]) -> tuple[int, list[str], list[dict]]:
    """
    Analyzes attachments for suspicious types and calculates hashes.
    Returns: (score, reasons, processed_attachments)
    """
    score = 0
    reasons = []
    processed_attachments = []
    
    risky_extensions = [".exe", ".scr", ".vbs", ".js", ".bat", ".cmd", ".ps1", ".jar"]
    office_extensions_ole = [".doc", ".xls", ".ppt"]
    office_extensions_xml = [".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"]

    for att in attachments:
        filename = att.get("filename", "").lower()
        content = att.get("content", b"")
        
        # Calculate hashes
        md5_hash = hashlib.md5(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()
        
        risk_label = "Clean"
        
        # Check Extension
        for ext in risky_extensions:
            if filename.endswith(ext):
                score += 20
                risk_label = "High Risk"
                reasons.append(f"Executable attachment detected: {filename}")
                break
        
        # Macro Detection
        try:
            # OLE Files (Legacy Office)
            if any(filename.endswith(ext) for ext in office_extensions_ole):
                if olefile.isOleFile(io.BytesIO(content)):
                    ole = olefile.OleFileIO(io.BytesIO(content))
                    if ole.exists('Macros') or ole.exists('_VBA_PROJECT_CUR') or ole.exists('VBA'):
                        score += 30
                        risk_label = "High Risk (Macros)"
                        reasons.append(f"Office Macros detected in OLE file: {filename}")
            
            # XML Files (Modern Office)
            if any(filename.endswith(ext) for ext in office_extensions_xml):
                if zipfile.is_zipfile(io.BytesIO(content)):
                    with zipfile.ZipFile(io.BytesIO(content)) as z:
                        # Standard macro location in OOXML
                        if 'word/vbaProject.bin' in z.namelist() or 'xl/vbaProject.bin' in z.namelist() or 'ppt/vbaProject.bin' in z.namelist():
                            score += 30
                            risk_label = "High Risk (Macros)"
                            reasons.append(f"Office Macros detected in XML file: {filename}")

        except Exception:
            # Parsing error, just continue
            pass
        
        processed_data = {
            "filename": filename,
            "md5": md5_hash,
            "sha256": sha256_hash,
            "risk": risk_label,
            "vt_stats": None,
            "signature": None
        }

        # Query VirusTotal if Key Exists
        if settings.VIRUSTOTAL_API_KEY:
            try:
                vt_url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
                headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
                async with aiohttp.ClientSession() as session:
                    async with session.get(vt_url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            attrs = data.get("data", {}).get("attributes", {})
                            
                            # Stats
                            stats = attrs.get("last_analysis_stats", {})
                            if stats:
                                malicious = stats.get("malicious", 0)
                                total = sum(stats.values())
                                processed_data["vt_stats"] = f"{malicious}/{total}"
                                if malicious > 0:
                                    score += (malicious * 5) # Increase score based on malicious hits
                                    reasons.append(f"Attachment '{filename}' flagged by {malicious} vendors in VirusTotal")
                                    processed_data["risk"] = "Malicious"

                            # Signature Info
                            sig_info = attrs.get("signature_info", {})
                            if sig_info:
                                processed_data["signature"] = {
                                    "product": sig_info.get("product", "Unknown"),
                                    "description": sig_info.get("description", "-"),
                                    "original_name": sig_info.get("original_name", "-"),
                                    "copyright": sig_info.get("copyright", "-"),
                                    "verified": sig_info.get("verified", "Unknown")
                                }
            except Exception as e:
                # print(f"VT Error: {e}") 
                pass

        processed_attachments.append(processed_data)
        
    return score, reasons, processed_attachments
