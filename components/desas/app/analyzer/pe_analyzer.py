import pefile
import math
import logging
from datetime import datetime

logger = logging.getLogger("uvicorn")

class PEAnalyzer:
    def __init__(self):
        self.suspicious_imports = [
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory", 
            "ShellExecute", "CreateRemoteThread", "OpenProcess", "GetProcAddress", 
            "LoadLibraryA", "LoadLibraryW", "WinExec", "InternetOpenA", "InternetOpenW",
            "URLDownloadToFileA", "URLDownloadToFileW", "CreateFileA", "CreateFileW",
            "WriteFile", "SetThreadContext", "ResumeThread"
        ]

    def analyze_pe(self, content_bytes: bytes, filename: str) -> dict:
        results = {
            "is_pe": False,
            "compile_time": None,
            "sections": [],
            "suspicious_imports": [],
            "imphash": None,
            "is_packed": False,
            "score": 0,
            "reasons": []
        }

        try:
            pe = pefile.PE(data=content_bytes)
            results["is_pe"] = True
            
            # 1. Compile Timestamp
            try:
                from datetime import timezone
                ts = pe.FILE_HEADER.TimeDateStamp
                results["compile_time"] = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                pass

            # 2. Imphash
            try:
                results["imphash"] = pe.get_imphash()
            except Exception:
                pass

            # 3. Sections & Entropy (Packing Detection)
            # High entropy (> 7.0) in code sections often indicates packing/encryption
            max_entropy = 0
            for section in pe.sections:
                entropy = self._get_entropy(section.get_data())
                s_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                results["sections"].append({"name": s_name, "entropy": round(entropy, 2)})
                if entropy > max_entropy:
                    max_entropy = entropy
                
                if entropy > 7.1 and s_name in ['.text', '.code']:
                    results["is_packed"] = True
                    if "High Entropy (Packed?)" not in results["reasons"]:
                        results["reasons"].append(f"High Entropy section ({s_name}): {entropy:.2f}")
                        results["score"] += 40

            # 4. Imports Analysis
            results["all_imports"] = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    results["all_imports"][dll_name] = []
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode('utf-8', errors='ignore')
                            results["all_imports"][dll_name].append(name)
                            if any(s.lower() == name.lower() for s in self.suspicious_imports):
                                if name not in results["suspicious_imports"]:
                                    results["suspicious_imports"].append(name)

            if results["suspicious_imports"]:
                count = len(results["suspicious_imports"])
                if count > 2:
                    results["score"] += min(count * 10, 50)
                    results["reasons"].append(f"Suspicious APIs detected: {', '.join(results['suspicious_imports'][:5])}")

        except pefile.PEFormatError:
            pass # Not a PE file
        except Exception as e:
            logger.error(f"PE Analysis failed for {filename}: {e}")

        return results

    def _get_entropy(self, data):
        if not data or len(data) == 0:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy
