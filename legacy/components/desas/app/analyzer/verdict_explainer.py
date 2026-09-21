"""
Verdict Explanation Engine

Aggregates risk factors from all analysis modules and generates
human-readable justifications for the final verdict.
"""

from typing import List, Dict, Any
from enum import Enum


class RiskCategory(str, Enum):
    AUTHENTICATION = "authentication"
    INFRASTRUCTURE = "infrastructure"
    CONTENT = "content"
    BEHAVIOR = "behavior"
    REPUTATION = "reputation"


class RiskSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VerdictExplainer:
    """Generates human-readable verdict explanations"""
    
    def __init__(self):
        self.risk_factors = []
        self.confidence_score = 0
    
    def add_risk_factor(
        self,
        category: RiskCategory,
        severity: RiskSeverity,
        evidence: str,
        score_contribution: int = 0
    ):
        """Add a risk factor to the explanation"""
        self.risk_factors.append({
            "category": category.value,
            "severity": severity.value,
            "evidence": evidence,
            "score_contribution": score_contribution
        })
    
    def analyze_authentication(self, auth_results: Dict, header_score: int) -> None:
        """Extract authentication risk factors"""
        if not auth_results:
            return
        
        # SPF failures
        spf = auth_results.get("spf", {})
        if spf.get("result") == "fail":
            self.add_risk_factor(
                RiskCategory.AUTHENTICATION,
                RiskSeverity.HIGH,
                "SPF validation failed (Sender IP not authorized)",
                15
            )
        elif spf.get("result") == "softfail":
            self.add_risk_factor(
                RiskCategory.AUTHENTICATION,
                RiskSeverity.MEDIUM,
                "SPF soft-fail detected (Questionable sender authorization)",
                10
            )
        
        # DKIM failures
        dkim = auth_results.get("dkim", {})
        if dkim.get("result") == "fail":
            self.add_risk_factor(
                RiskCategory.AUTHENTICATION,
                RiskSeverity.HIGH,
                "DKIM signature failed (Message integrity compromised)",
                15
            )
        
        # DMARC failures
        dmarc = auth_results.get("dmarc", {})
        if dmarc.get("result") == "fail":
            self.add_risk_factor(
                RiskCategory.AUTHENTICATION,
                RiskSeverity.CRITICAL,
                "DMARC validation failed (Policy misalignment detected)",
                20
            )
        elif dmarc.get("policy") == "none":
            self.add_risk_factor(
                RiskCategory.AUTHENTICATION,
                RiskSeverity.MEDIUM,
                "DMARC policy not enforced (p=none allows spoofing)",
                10
            )
    
    def analyze_infrastructure(self, ip_intel: Dict, mxtoolbox: Dict) -> None:
        """Extract infrastructure risk factors"""
        if not ip_intel:
            return
        
        for ip, intel in ip_intel.items():
            # Check abuse score
            abuse_score = intel.get("abuse_score", 0)
            if isinstance(intel.get("reputation"), dict):
                abuse_score = intel["reputation"].get("abuse_score", 0)
            
            if abuse_score > 50:
                self.add_risk_factor(
                    RiskCategory.INFRASTRUCTURE,
                    RiskSeverity.CRITICAL,
                    f"High abuse score for {ip} ({abuse_score}% - Known malicious activity)",
                    20
                )
            elif abuse_score > 10:
                self.add_risk_factor(
                    RiskCategory.INFRASTRUCTURE,
                    RiskSeverity.MEDIUM,
                    f"Moderate abuse score for {ip} ({abuse_score}% - Previous reports)",
                    10
                )
        
        # MxToolbox failures
        if mxtoolbox:
            for check, result in mxtoolbox.items():
                if isinstance(result, dict) and not result.get("passed"):
                    self.add_risk_factor(
                        RiskCategory.INFRASTRUCTURE,
                        RiskSeverity.MEDIUM,
                        f"MxToolbox {check.upper()} check failed",
                        5
                    )
    
    def analyze_content(self, body_reasons: List[str], html_analysis: Dict) -> None:
        """Extract content risk factors"""
        for reason in body_reasons:
            severity = RiskSeverity.MEDIUM
            score = 10
            
            if "credential" in reason.lower() or "password" in reason.lower():
                severity = RiskSeverity.CRITICAL
                score = 20
            elif "suspicious" in reason.lower() or "phish" in reason.lower():
                severity = RiskSeverity.HIGH
                score = 15
            
            self.add_risk_factor(
                RiskCategory.CONTENT,
                severity,
                reason,
                score
            )
        
        # HTML analysis
        if html_analysis:
            if html_analysis.get("credential_harvesting"):
                self.add_risk_factor(
                    RiskCategory.CONTENT,
                    RiskSeverity.CRITICAL,
                    "Credential harvesting detected (Password input field found)",
                    25
                )
            
            if html_analysis.get("external_forms"):
                self.add_risk_factor(
                    RiskCategory.CONTENT,
                    RiskSeverity.HIGH,
                    "External form submission detected (Data exfiltration risk)",
                    15
                )
    
    def analyze_behavior(self, sandbox_results: List[Dict]) -> None:
        """Extract behavioral risk factors"""
        if not sandbox_results:
            return
        
        credential_count = 0
        post_count = 0
        redirect_count = 0
        
        for sandbox in sandbox_results:
            reasons = sandbox.get("reasons", [])
            
            for reason in reasons:
                reason_lower = reason.lower()
                
                if "credential" in reason_lower or "password" in reason_lower:
                    credential_count += 1
                
                if "post" in reason_lower or "exfil" in reason_lower:
                    post_count += 1
                
                if "redirect" in reason_lower:
                    redirect_count += 1
        
        # Behavioral patterns
        if credential_count > 0:
            self.add_risk_factor(
                RiskCategory.BEHAVIOR,
                RiskSeverity.CRITICAL,
                f"Credential harvesting behavior detected in {credential_count} sandbox(es)",
                20
            )
        
        if post_count > 0:
            self.add_risk_factor(
                RiskCategory.BEHAVIOR,
                RiskSeverity.HIGH,
                f"POST request exfiltration observed in {post_count} sandbox(es)",
                15
            )
        
        if redirect_count >= 3:
            self.add_risk_factor(
                RiskCategory.BEHAVIOR,
                RiskSeverity.MEDIUM,
                f"Multiple redirects detected ({redirect_count} - Evasion technique)",
                10
            )
    
    def analyze_reputation(self, url_intel: Dict, suspicious_domains: List[str]) -> None:
        """Extract reputation risk factors"""
        if url_intel:
            for target, intel in url_intel.items():
                hits = intel.get("hits", intel.get("malicious", 0))
                
                if hits > 5:
                    self.add_risk_factor(
                        RiskCategory.REPUTATION,
                        RiskSeverity.CRITICAL,
                        f"High VirusTotal detections for {target} ({hits} engines)",
                        20
                    )
                elif hits > 0:
                    self.add_risk_factor(
                        RiskCategory.REPUTATION,
                        RiskSeverity.HIGH,
                        f"VirusTotal detections for {target} ({hits} engines)",
                        15
                    )
                elif hits == 0 and intel.get("type") == "domain":
                    # Clean VT scan - add as INFO to show we checked
                    self.add_risk_factor(
                        RiskCategory.REPUTATION,
                        RiskSeverity.INFO,
                        f"VirusTotal scan clean for {target} (0 detections)",
                        0
                    )
        
        if suspicious_domains:
            for domain in suspicious_domains:
                self.add_risk_factor(
                    RiskCategory.REPUTATION,
                    RiskSeverity.MEDIUM,
                    f"Suspicious domain detected: {domain}",
                    10
                )
    
    def analyze_whitelist(self, whitelisted_domains: List[str]) -> None:
        """Add positive indicators for whitelisted domains"""
        if whitelisted_domains:
            for domain in whitelisted_domains:
                self.add_risk_factor(
                    RiskCategory.INFRASTRUCTURE,
                    RiskSeverity.INFO,
                    f"Trusted domain whitelisted: {domain} (False positive prevention)",
                    0
                )
    
    def calculate_confidence(self, total_score: int) -> int:
        """Calculate confidence score based on evidence diversity"""
        # Count unique categories
        categories = set(rf["category"] for rf in self.risk_factors)
        category_count = len(categories)
        
        # Count critical/high severity factors
        high_severity = sum(
            1 for rf in self.risk_factors 
            if rf["severity"] in ["critical", "high"]
        )
        
        # Base confidence on evidence diversity and severity
        confidence = 50  # Base confidence
        
        # More categories = higher confidence
        confidence += category_count * 10
        
        # More high-severity factors = higher confidence
        confidence += min(high_severity * 5, 30)
        
        # Score alignment
        if total_score >= 71:  # Malicious
            confidence += 10
        elif total_score >= 31:  # Suspicious
            confidence += 5
        
        return min(confidence, 100)
    
    def generate_explanation(self, verdict: str, total_score: int) -> str:
        """Generate human-readable verdict explanation"""
        if not self.risk_factors:
            return f"Email classified as {verdict} based on automated analysis."
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_factors = sorted(
            self.risk_factors,
            key=lambda x: severity_order.get(x["severity"], 5)
        )
        
        # Build explanation
        lines = [f"**Why this email is classified as {verdict.upper()}**\n"]
        
        for factor in sorted_factors[:5]:  # Top 5 factors
            emoji = {
                "critical": "🚨",
                "high": "⚠️",
                "medium": "⚡",
                "low": "ℹ️",
                "info": "💡"
            }.get(factor["severity"], "•")
            
            lines.append(f"{emoji} {factor['evidence']}")
        
        if len(sorted_factors) > 5:
            lines.append(f"\n...and {len(sorted_factors) - 5} additional indicators")
        
        return "\n".join(lines)
    
    def get_results(self, verdict: str, total_score: int) -> Dict[str, Any]:
        """Get complete explanation results"""
        self.confidence_score = self.calculate_confidence(total_score)
        
        return {
            "verdict_explanation": self.generate_explanation(verdict, total_score),
            "risk_factors": self.risk_factors,
            "confidence_score": self.confidence_score
        }


def explain_verdict(analysis_data: Dict) -> Dict[str, Any]:
    """
    Main entry point for verdict explanation
    
    Args:
        analysis_data: Complete analysis result dictionary
    
    Returns:
        Dictionary with explanation, risk_factors, and confidence_score
    """
    explainer = VerdictExplainer()
    
    # Analyze all components
    explainer.analyze_authentication(
        analysis_data.get("auth_results", {}),
        analysis_data.get("header_score", 0)
    )
    
    explainer.analyze_infrastructure(
        analysis_data.get("ip_intel", {}),
        analysis_data.get("mxtoolbox_analysis", {})
    )
    
    explainer.analyze_content(
        analysis_data.get("body_reasons", []),
        analysis_data.get("html_analysis", {})
    )
    
    explainer.analyze_behavior(
        analysis_data.get("sandbox_results", [])
    )
    
    explainer.analyze_reputation(
        analysis_data.get("url_intel", {}),
        analysis_data.get("suspicious_domains", [])
    )
    
    # Analyze whitelisted domains (positive indicators)
    explainer.analyze_whitelist(
        analysis_data.get("whitelisted_domains", [])
    )
    
    return explainer.get_results(
        analysis_data.get("verdict", "Unknown"),
        analysis_data.get("total_score", 0)
    )
