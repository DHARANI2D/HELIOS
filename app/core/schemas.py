from pydantic import BaseModel
from typing import List, Optional, Dict

class NetworkRequest(BaseModel):
    url: str
    method: str
    domain: str

class AnalysisResult(BaseModel):
    # Meta
    subject: str = ""
    sender: str = ""
    
    # Modular Scores
    header_score: int = 0
    header_reasons: List[str] = []
    
    body_score: int = 0
    body_reasons: List[str] = []
    
    sandbox_score: int = 0
    sandbox_reasons: List[str] = []
    
    # Sandbox Evidence
    url: str  # The analyzed URL
    expanded_url: str
    redirect_chain: List[str]
    screenshot_path: Optional[str] = None
    network_requests: List[NetworkRequest]
    dom_mutations: List[str]
    network_requests: List[NetworkRequest]
    dom_mutations: List[str]
    suspicious_domains: List[str] = []
    extracted_urls: List[str] = []
    extracted_urls: List[str] = []
    attachments: List[Dict] = []
    mxtoolbox_analysis: Dict = {}
    whitelisted_domains: List[str] = []
    
    # Final Verdict
    total_score: int = 0
    verdict: str = "Pending"
    risk_reasons: List[str] = []  # Aggregate of all reasons
    block_recommendations: List[str] = []
    
    # Header Visualization
    hops: List[Dict] = []
    auth_results: Dict = {}
    all_headers: List[Dict] = []
