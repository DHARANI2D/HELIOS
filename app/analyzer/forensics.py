import math
import re
import zipfile
import io
import logging
from collections import Counter
from typing import Dict, List, Any

logger = logging.getLogger("uvicorn")

# -------- CORE ANALYTICS --------

def shannon_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte string."""
    if not data:
        return 0.0
    freq = Counter(data)
    probs = [c / len(data) for c in freq.values()]
    return -sum(p * math.log2(p) for p in probs)

def obfuscation_heuristics(data: str) -> int:
    """Detects common obfuscation patterns in scripts (VBA, JS, etc.)"""
    score = 0
    if not data:
        return 0
        
    low_data = data.lower()
    
    # Character code usage
    if re.search(r'chr\(\d+\)', low_data):
        score += 20
        
    # Heavy string concatenation
    if data.count("+") > 50 or data.count("&") > 50:
        score += 15
        
    # Long encoded-looking blobs (Base64-ish)
    if re.search(r'[A-Za-z0-9+/=]{80,}', data):
        score += 25
        
    # Mixed case/randomized case detection (heuristics)
    # If the ratio of uppercase to lowercase is very balanced in a large string, it might be obfuscated
    if len(data) > 100:
        alphas = [c for c in data if c.isalpha()]
        if alphas:
            u_count = sum(1 for c in alphas if c.isupper())
            ratio = u_count / len(alphas)
            if 0.3 < ratio < 0.7:
                score += 10
                
    return score

def vba_semantic_analysis(vba_code: str) -> Dict[str, Any]:
    """Analyzes VBA code intent beyond simple existence."""
    indicators = {
        "auto_exec": False,
        "env_fingerprinting": False,
        "staging_logic": False,
        "obfuscation": False,
        "suspicious_calls": []
    }
    
    if not vba_code:
        return indicators
        
    vba_low = vba_code.lower()
    
    # 1. Execution Triggers
    auto_execs = ["auto_open", "workbook_open", "document_open", "auto_exec", "autoopen"]
    indicators["auto_exec"] = any(x in vba_low for x in auto_execs)
    
    # 2. Environment Awareness (Anti-VM / Anti-Sandbox)
    env_calls = ["environ", "username", "computername", "getobject(\"winmgmts:", "win32_process"]
    indicators["env_fingerprinting"] = any(x in vba_low for x in env_calls)
    
    # 3. Payload Staging
    staging_keywords = ["split(", "join(", "replace(", "chr(", "strconv(", "getbyte"]
    # If multiple staging keywords are used heavily
    indicators["staging_logic"] = sum(1 for x in staging_keywords if x in vba_low) >= 2
    
    # 4. Critical External Calls
    susp_calls_map = {
        "shell": "Shell execution",
        "wscript.shell": "WScript interaction",
        "powershell": "PowerShell invocation",
        "createobject": "Dynamic object creation",
        "adodb.stream": "File system stream (Dropper logic)",
        "xmlhttp": "Network download (XMLHTTP)",
        "winhttprequest": "Network download (WinHTTP)",
        "urlretrieve": "Network download",
        "base64": "Encoded payload"
    }
    
    for call, desc in susp_calls_map.items():
        if call in vba_low:
            indicators["suspicious_calls"].append(desc)
            
    # 5. Obfuscation check
    indicators["obfuscation"] = vba_low.count("chr(") > 10 or "strreverse" in vba_low
    
    return indicators

def structural_analysis(content: bytes, filename: str) -> Dict[str, Any]:
    """Analyzes the file structure for anomalies (ZIP/Office)."""
    findings = {
        "extra_data": False, # ZIP overlay/anomaly
        "unexpected_files": [],
        "structure_score": 0,
        "is_archive": False
    }
    
    if not content:
        return findings
        
    # Check if it's a ZIP-based file
    if zipfile.is_zipfile(io.BytesIO(content)):
        findings["is_archive"] = True
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                for f in z.infolist():
                    # Check for potential payload staging in archives
                    ext = "." + f.filename.split(".")[-1].lower() if "." in f.filename else ""
                    risky_exts = [".exe", ".dll", ".js", ".vbs", ".ps1", ".vbe", ".jse", ".cmd", ".bat"]
                    
                    if ext in risky_exts:
                        findings["unexpected_files"].append(f.filename)
                        findings["structure_score"] += 30
                        
                    # Double extension check
                    if re.search(r'\.[a-z0-9]{2,4}\.(exe|js|vbs|bat|cmd)$', f.filename.lower()):
                        findings["unexpected_files"].append(f"{f.filename} (Potential Masquerading)")
                        findings["structure_score"] += 20
                        
                    # Encrypted/Password protected files
                    if f.flag_bits & 0x1:
                        findings["unexpected_files"].append(f"{f.filename} (Encrypted)")
                        findings["structure_score"] += 15
                        
        except Exception as e:
            logger.warning(f"Structural analysis failed for {filename}: {e}")
            
    return findings

def detect_polyglots(content: bytes) -> List[str]:
    """Identifies multiple file signatures in a single file buffer."""
    findings = []
    if len(content) < 100:
        return findings
        
    signatures = {
        b"PK\x03\x04": "ZIP/Office",
        b"%PDF": "PDF",
        b"\xff\xd8\xff": "JPEG",
        b"\x89PNG\r\n\x1a\n": "PNG",
        b"MZ": "PE Executable",
        b"BM": "BMP",
        b"GIF8": "GIF",
        b"\x7fELF": "ELF Executable"
    }
    
    found = []
    for sig, label in signatures.items():
        if sig in content:
            found.append(label)
            
    if len(found) > 1:
        # Check if they are sufficiently far apart to not be false positives or standard nesting
        # A PDF can contain a ZIP (ObjStm), but a PDF starting with MZ at offset 0 is a polyglot
        findings.append(f"Polyglot Indicators: {', '.join(found)}")
        
    # Check for Appended Data (EOF Anomaly)
    # If a PNG has a PE/ZIP signature at the very end
    image_sigs = [b"\xff\xd9", b"\x00\x00\x00\x00IEND\xaeB`\x82"] # JPEG/PNG EOF
    for eof in image_sigs:
        if eof in content:
            eof_pos = content.rfind(eof) + len(eof)
            if len(content) > eof_pos + 10:
                # Extra data found after image EOF
                extra = content[eof_pos:]
                if any(s in extra for s in [b"MZ", b"PK\x03\x04", b"powershell"]):
                    findings.append("Appended malicious payload detected after image EOF")
                    
    return findings

def analyze_ole_streams(content: bytes) -> Dict[str, Any]:
    """Scans OLE streams for specific malicious indicators beyond basic macros."""
    import olefile
    indicators = {
        "risky_streams": [],
        "ole_anomalies": False
    }
    
    if not olefile.isOleFile(io.BytesIO(content)):
        return indicators
        
    try:
        ole = olefile.OleFileIO(io.BytesIO(content))
        streams = [s[0] if isinstance(s, list) else s for s in ole.listdir()]
        
        target_streams = {
            "MBDG": "Potentially obfuscated shellcode stream",
            "Package": "Embedded OLE Package (often an EXE)",
            "Equation Native": "Equation Editor Exploit (CVE-2017-11882)",
            "Ole10Native": "Embedded Native code/binary",
            "ObjectPool": "Nested OLE objects (Evasion)"
        }
        
        for name, desc in target_streams.items():
            if any(name.lower() in str(s).lower() for s in streams):
                indicators["risky_streams"].append(desc)
                indicators["ole_anomalies"] = True
                
    except Exception as e:
        logger.warning(f"OLE Stream analysis failed: {e}")
        
    return indicators

def detect_xlm_macros(vba_code: str, raw_bytes: bytes) -> List[str]:
    """Detects Legacy Excel 4.0 (XLM) macros which are often used for evasion."""
    findings = []
    # XLM macros often use specific functions that show up in raw bytes or strings
    xlm_patterns = [
        rb"EXEC", rb"REGISTER", rb"CALL", rb"HALT", rb"RUN", rb"CHAR",
        rb"GET.WINDOW", rb"WINDOW.HIDE", rb"WORKBOOK.HIDE"
    ]
    
    found_ops = []
    for p in xlm_patterns:
        if p in raw_bytes:
            found_ops.append(p.decode())
            
    if len(found_ops) >= 3:
        findings.append(f"Excel 4.0 (XLM) Macro pattern detected: {', '.join(found_ops)}")
        
    return findings

def pdf_forensic_signals(text_content: str, raw_bytes: bytes) -> Dict[str, Any]:
    """Deep PDF analysis for evasion and suspicious objects."""
    signals = {
        "has_js": False,
        "has_launch": False,
        "embedded_files": False,
        "evasion_detected": False,
        "suspicious_tags": []
    }
    
    # We use regex on raw bytes for tags that usually trigger SOC hits
    try:
        raw_str = raw_bytes.decode('utf-8', errors='ignore').lower()
        
        tag_map = {
            "/javascript": ("has_js", "Javascript code"),
            "/js": ("has_js", "Javascript code (short)"),
            "/launch": ("has_launch", "Launch action (EXE execution)"),
            "/embeddedfile": ("embedded_files", "Embedded file payload"),
            "/richtext": ("suspicious_tags", "Rich text content"),
            "/openaction": ("suspicious_tags", "Auto-open action"),
            "/aa": ("suspicious_tags", "Additional Action (Auto-trigger)")
        }
        
        for tag, (key, desc) in tag_map.items():
            if tag in raw_str:
                if isinstance(signals[key], bool):
                    signals[key] = True
                else:
                    signals[key].append(desc)
                    
        # Evasion detection (e.g., ObjStm without XRef - very basic check)
        if "/objstm" in raw_str and "/xref" not in raw_str:
            signals["evasion_detected"] = True
            
    except Exception:
        pass
        
    return signals

def infer_mitre_techniques(signals: Dict[str, Any]) -> List[str]:
    """Maps forensic signals to MITRE ATT\u0026CK techniques."""
    tech_map = {
        "auto_exec": "T1204.002", # User Execution: Malicious File
        "obfuscation": "T1027",    # Obfuscated Files or Information
        "env_fingerprinting": "T1497", # Virtualization/Sandbox Evasion
        "staging_logic": "T1059",  # Command and Scripting Interpreter
        "has_macros": "T1059.005", # Visual Basic
        "has_js": "T1059.007",     # JavaScript
        "double_extension": "T1036.007", # Masquerading: Double Extension
        "zip_then_excel": "T1566.001", # Phishing: Spearphishing Attachment
        "polyglot": "T1027.001",   # Binary Padding / Polyglot
        "ole_anomaly": "T1204.002", # Malicious File (OLE)
        "xlm_macro": "T1059",      # Command and Scripting Interpreter
        "appended_data": "T1027.001" # Binary Padding
    }
    
    techniques = []
    for sig, tech in tech_map.items():
        if signals.get(sig):
            techniques.append(tech)
            
    return sorted(list(set(techniques)))

def analyze_image_forensics(exif_data: Dict[str, Any], raw_bytes: bytes) -> Dict[str, Any]:
    """Heuristic check for steganography or suspicious metadata."""
    results = {
        "suspicious": False,
        "reasons": []
    }
    
    # Check entropy of the entire image (high entropy can indicate hidden payloads)
    e = shannon_entropy(raw_bytes)
    if e > 7.9:
        results["suspicious"] = True
        results["reasons"].append("Extremely high entropy (Potential Payload)")
        
    # Check EXIF for scripty looking strings
    if exif_data:
        script_indicators = ["script", "powershell", "curl", "wget", "http", "<?php", "exec("]
        for val in exif_data.values():
            if isinstance(val, str):
                v_low = val.lower()
                if any(x in v_low for x in script_indicators):
                    results["suspicious"] = True
                    results["reasons"].append(f"Suspicious string in metadata: {val[:30]}...")
                    
    return results
