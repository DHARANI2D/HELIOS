import re
import math
import base64
import zlib
from collections import Counter
from typing import List, Dict, Any, Optional

class ExfiltrationEngine:
    def __init__(self):
        # Professional PII Patterns
        self.pii_patterns = {
            "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "Aadhaar": r"\b\d{4}\s\d{4}\s\d{4}\b",
            "Target Local ID": r"\b\d{4}-\d{4}-\d{4}\b",
            "Private Key": r"-----BEGIN (?:RSA |EC |)PRIVATE KEY-----",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Generic API Key": r"(?:key|api|token|secret|auth)[-|_|\s]*[:|=][-|_|\s]*[a-zA-Z0-9]{16,}"
        }

    def calculate_entropy(self, data: str) -> float:
        """Calculates Shannon Entropy of a string."""
        if not data:
            return 0.0
        prob = [n_x / len(data) for x, n_x in Counter(data).items()]
        return -sum(p * math.log(p, 2) for p in prob)

    def luhn_check(self, card_number: str) -> bool:
        """Validates a credit card number using the Luhn algorithm."""
        digits = [int(d) for d in re.sub(r"\D", "", card_number)]
        if not digits: return False
        checksum = digits[-1]
        payload = digits[:-1][::-1]
        for i, d in enumerate(payload):
            if i % 2 == 0:
                d *= 2
                if d > 9: d -= 9
            checksum += d
        return checksum % 10 == 0

    def detect_secrets(self, data: str) -> List[str]:
        """Scans data for PII and secrets with validation."""
        found = []
        for label, pattern in self.pii_patterns.items():
            matches = re.findall(pattern, data, re.IGNORECASE)
            for m in matches:
                if label == "Credit Card":
                    if self.luhn_check(m):
                        found.append(f"{label} (Validated)")
                else:
                    found.append(label)
        return list(set(found))

    def recursive_decode(self, data: str, depth: int = 0, max_depth: int = 4) -> Dict[str, Any]:
        """Decodes nested payloads (Base64, Hex, Gzip)."""
        if depth > max_depth or not data:
            return {"final_content": data, "layers": depth, "signals": []}

        signals = []
        decoded = None
        
        # Try Base64
        if re.match(r"^[A-Za-z0-9+/=]+$", data.strip()) and len(data.strip()) > 16:
            try:
                raw_decoded = base64.b64decode(data.strip())
                signals.append("Base64")
                # Try Gzip/Zlib within B64
                try:
                    decoded = zlib.decompress(raw_decoded, 16 + zlib.MAX_WBITS).decode('utf-8', errors='ignore')
                    signals.append("Gzip")
                except:
                    try:
                        decoded = zlib.decompress(raw_decoded).decode('utf-8', errors='ignore')
                        signals.append("Zlib")
                    except:
                        decoded = raw_decoded.decode('utf-8', errors='ignore')
            except: pass

        # Try Hex
        if not decoded and re.match(r"^[0-9a-fA-F\s]+$", data.strip()) and len(data.strip()) > 32:
            try:
                decoded = bytes.fromhex(data.strip().replace(" ", "")).decode('utf-8', errors='ignore')
                signals.append("Hex")
            except: pass

        if decoded and decoded != data:
            inner = self.recursive_decode(decoded, depth + 1, max_depth)
            return {
                "final_content": inner["final_content"],
                "layers": inner["layers"],
                "signals": list(set(signals + inner["signals"]))
            }

        return {"final_content": data, "layers": depth, "signals": signals}

    def analyze_dns_tunneling(self, subdomain: str, domain: str) -> Dict[str, Any]:
        """Analyzes subdomains for DNS tunneling indicators."""
        if not subdomain:
            return {"detected": False, "score": 0, "reasons": []}
        
        entropy = self.calculate_entropy(subdomain)
        length = len(subdomain)
        parts = subdomain.count('.') + 1
        
        score = 0
        reasons = []
        
        if entropy > 4.5:
            score += 40
            reasons.append(f"High Shannon entropy ({entropy:.2f})")
        if length > 50:
            score += 30
            reasons.append(f"Excessive length ({length} chars)")
        if parts > 3:
            score += 20
            reasons.append(f"Deep subdomain hierarchy ({parts} levels)")
            
        return {
            "detected": score >= 50,
            "score": score,
            "reasons": reasons,
            "metrics": {"entropy": entropy, "length": length, "depth": parts}
        }

    def process_payload(self, data: str, subdomain: str = "", domain: str = "") -> Dict[str, Any]:
        """Full SOC-grade correlation of network data."""
        # 1. Decode
        decode_res = self.recursive_decode(data)
        content = decode_res["final_content"]
        
        # 2. Detect Secrets
        secrets = self.detect_secrets(content)
        
        # 3. Entropy
        entropy = self.calculate_entropy(content)
        
        # 4. DNS
        dns_res = self.analyze_dns_tunneling(subdomain, domain)
        
        return {
            "pii_detected": secrets,
            "entropy": entropy,
            "dns_tunneling": dns_res["detected"],
            "dns_reasons": dns_res["reasons"],
            "obfuscation_layers": decode_res["layers"],
            "obfuscation_signals": decode_res["signals"],
            "is_malicious": len(secrets) > 0 or dns_res["detected"] or entropy > 5.0
        }
