import re
from typing import List, Dict, Any

class SemanticFirewall:
    """Detects malicious intent, jailbreaks, and prompt injections."""
    
    # Red teaming patterns / Jailbreak cues
    SUSPICIOUS_PATTERNS = [
        r"(?i)ignore (all )?previous instructions",
        r"(?i)system prompt",
        r"(?i)dan mode",
        r"(?i)jailbreak",
        r"(?i)sudo execute",
        r"(?i)base64 decode this",
        r"(?i)bypass policy"
    ]

    def __init__(self):
        self.patterns = [re.compile(p) for p in self.SUSPICIOUS_PATTERNS]

    def scan_input(self, text: str) -> Dict[str, Any]:
        """Scans AI input for potential jailbreaks."""
        matches = []
        for p in self.patterns:
            if p.search(text):
                matches.append(p.pattern)
        
        if matches:
            return {
                "safe": False,
                "threat_type": "PROMPT_INJECTION",
                "detected_patterns": matches
            }
        return {"safe": True}

class AIDLP:
    """Scans and redacts PII/Secrets from AI inputs and outputs."""
    
    # Regex-based scanner for MVP (Enterprise would use ML-based entity extraction)
    PII_PATTERNS = {
        "EMAIL": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "IP_ADDRESS": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "API_KEY": r"(?i)(api[_-]?key|secret|token)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?"
    }

    def __init__(self):
        self.patterns = {k: re.compile(v) for k, v in self.PII_PATTERNS.items()}

    def scan_and_redact(self, text: str) -> Dict[str, Any]:
        """Redacts PII from text and returns metadata."""
        redacted_text = text
        found_entities = []
        
        for entity_type, pattern in self.patterns.items():
            matches = pattern.findall(text)
            if matches:
                found_entities.extend([(entity_type, m) for m in matches])
                redacted_text = pattern.sub(f"[REDACTED_{entity_type}]", redacted_text)
        
        return {
            "original_text": text,
            "redacted_text": redacted_text,
            "blocked_entities": found_entities,
            "safe": len(found_entities) == 0
        }
