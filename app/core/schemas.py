from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class NetworkRequest(BaseModel):
    url: str
    method: str
    domain: str

class HeaderRequest(BaseModel):
    headers: str

class URLRequest(BaseModel):
    url: str

class DomainRequest(BaseModel):
    domain: str

class IPRequest(BaseModel):
    ip: str

class ReportRequest(BaseModel):
    ip: str
    categories: List[int]
    comment: str

class SandboxResult(BaseModel):
    url: str
    expanded_url: str = ""
    redirect_chain: List[str] = []
    screenshot_path: Optional[str] = None
    screenshot_chain: List[Dict[str, str]] = []
    network_requests: List[NetworkRequest] = []
    dom_mutations: List[str] = []
    detected_forms: List[Dict] = []
    exfiltration_detected: Optional[Dict] = None
    js_analysis: List[Dict] = []
    score: int = 0
    reasons: List[str] = []
    status: str = "pending" # pending, complete, error
    api_quotas: Dict[str, Any] = {}

class AnalysisResult(BaseModel):
    # Meta
    subject: str = ""
    sender: str = ""
    recipient: str = ""
    date: str = ""
    primary_body_html: str = ""
    primary_body_screenshot: Optional[str] = None
    status: str = "pending"
    
    # Modular Scores
    header_score: int = 0
    header_reasons: List[str] = []
    header_status: str = "pending"
    
    body_score: int = 0
    body_reasons: List[str] = []
    body_status: str = "pending"
    
    sandbox_score: int = 0
    sandbox_reasons: List[str] = []
    sandbox_status: str = "pending"
    
    # Sandbox Evidence (Legacy support for first result)
    url: str = "" 
    expanded_url: str = ""
    redirect_chain: List[str] = []
    screenshot_path: Optional[str] = None
    screenshot_chain: List[Dict[str, str]] = [] # list of {"url": ..., "path": ...}
    network_requests: List[NetworkRequest] = []
    dom_mutations: List[str] = []
    
    # Multi-Sandbox Results
    sandbox_results: List[SandboxResult] = []
    
    suspicious_domains: List[str] = []
    domain_age_days: Dict[str, int] = {} # domain -> age in days
    extracted_urls: List[str] = []
    attachments: List[Dict] = []
    mxtoolbox_analysis: Dict = {}
    dns_details: Dict = {} # domain -> list of records
    url_intel: Dict[str, Dict] = {} # url/domain -> detailed intel (hits, age, etc)
    ip_intel: Dict = {} # ip -> intel
    whitelisted_domains: List[str] = []
    
    # Advanced Sandbox Evidence (Legacy)
    detected_forms: List[Dict] = []
    exfiltration_detected: Optional[Dict] = None
    js_analysis: List[Dict] = []
    html_analysis: Dict[str, Any] = {}
    
    # Final Verdict
    total_score: int = 0
    verdict: str = "Pending"
    threat_type: str = "Unknown" # e.g., Phishing, Malware, Spam
    threat_category: str = "None" # e.g., Emotet, Qakbot, Credential Harvesting
    risk_reasons: List[str] = []  # Aggregate of all reasons
    block_recommendations: List[str] = []
    
    # Verdict Explanation (Phase 1 Enhancement)
    verdict_explanation: str = ""
    risk_factors: List[Dict[str, Any]] = []
    confidence_score: int = 0
    
    # Score Decomposition (Phase 7 Enhancement)
    score_breakdown: List[Dict[str, Any]] = []
    
    # Header Visualization
    hops: List[Dict] = []
    auth_results: Dict = {}
    all_headers: List[Dict] = []
    api_quotas: Dict[str, Any] = {}
