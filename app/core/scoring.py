from app.core.schemas import AnalysisResult, NetworkRequest, SandboxResult

def calculate_sandbox_score(result_obj: SandboxResult) -> tuple[int, list[str], list[str]]:
    """
    Recalculates just the sandbox portion of the score for a specific result.
    Returns: (score, reasons, blocking_recs)
    """
    score = 0
    reasons = []
    recs = []

    # Rule 1: Password field detected
    if "interacted_with_form" in str(result_obj.dom_mutations) or any("password" in f.get("name", "").lower() for form in result_obj.detected_forms for f in form.get("fields", [])):
        score += 40
        reasons.append(f"Sandbox ({result_obj.url}): Password input field detected (Credential Harvesting)")
        recs.append(f"Block URL: {result_obj.expanded_url}")

    # Rule 2: Redirect chain length
    if len(result_obj.redirect_chain) > 2:
        score += 10
        reasons.append(f"Sandbox ({result_obj.url}): Long redirect chain ({len(result_obj.redirect_chain)} hops)")
    
    # Rule 4: Data Exfiltration Check (Verified)
    if result_obj.exfiltration_detected:
        score += 100
        reasons.append(f"CRITICAL ({result_obj.url}): Verified Data Exfiltration detected! Dummy credentials sent to {result_obj.exfiltration_detected['target_url']}")
        recs.append(f"Block Data Exfil Target: {result_obj.exfiltration_detected['target_url']}")
    elif any(req.method == "POST" for req in result_obj.network_requests):
        score += 20
        reasons.append(f"Sandbox ({result_obj.url}): Generic POST requests detected (Potential Exil)")

    # Rule 5: JS Behavioral Analysis
    for script in result_obj.js_analysis:
        if script.get("flags"):
            score += 10 * len(script["flags"])
            for flag in script["flags"]:
                reasons.append(f"Sandbox ({result_obj.url}): High-risk JS detected: {flag} in {script['script']}")

    # Block original URL if suspicious
    if score >= 20:
        recs.append(f"Block Entry URL: {result_obj.url}")

    return score, reasons, recs

def aggregate_verdict(result: AnalysisResult) -> AnalysisResult:
    """
    Combines Header, Body, and Sandbox scores into a final verdict.
    """
    total_sb_score = 0
    total_sb_reasons = []
    total_sb_recs = set()

    # Process all sandbox results
    for i, sb_result in enumerate(result.sandbox_results):
        score, reasons, recs = calculate_sandbox_score(sb_result)
        sb_result.score = score
        sb_result.reasons = reasons
        
        total_sb_score += score
        total_sb_reasons.extend(reasons)
        for r in recs:
            total_sb_recs.add(r)
            
        # For legacy UI support, populate the main fields with the first result
        if i == 0:
            result.url = sb_result.url
            result.expanded_url = sb_result.expanded_url
            result.redirect_chain = sb_result.redirect_chain
            result.screenshot_path = sb_result.screenshot_path
            result.screenshot_chain = sb_result.screenshot_chain
            result.network_requests = sb_result.network_requests
            result.dom_mutations = sb_result.dom_mutations
            result.detected_forms = sb_result.detected_forms
            result.exfiltration_detected = sb_result.exfiltration_detected
            result.js_analysis = sb_result.js_analysis

    result.sandbox_score = total_sb_score
    result.sandbox_reasons = total_sb_reasons
    
    # 2. Total Score
    total_score = result.header_score + result.body_score + result.sandbox_score
    result.total_score = total_score
    
    # 3. Aggregate Reasons & Recommendations
    all_reasons = result.header_reasons + result.body_reasons + result.sandbox_reasons
    result.risk_reasons = all_reasons
    
    # Merge block recommendations
    current_recs = set(result.block_recommendations)
    for r in total_sb_recs:
        current_recs.add(r)
    result.block_recommendations = list(current_recs)

    # 4. Final Verdict (SOC Blueprint Thresholds)
    # 0–30 → Benign
    # 31–70 → Suspicious
    # 71+ → Malicious
    
    if total_score >= 71:
        result.verdict = "Malicious"
    elif total_score >= 31:
        result.verdict = "Suspicious"
    else:
        result.verdict = "Benign"

    # 5. Threat Classification
    if result.verdict != "Benign":
        # Indicators
        mal_k = ["malicious", "flagged by", "macro", "trojan", "virus", "ransomware"]
        phi_k = ["password", "credential", "login", "young", "newly registered"]
        
        has_phish = any(k in r.lower() for r in all_reasons for k in phi_k)
        has_mal = any(k in r.lower() for r in all_reasons for k in mal_k)
        
        if has_phish:
             result.threat_type = "Phishing"
             if any(k in r.lower() for r in all_reasons for k in ["password", "credential", "login"]):
                 result.threat_category = "Credential Harvesting"
             elif any("young" in r.lower() or "newly registered" in r.lower() for r in all_reasons):
                 result.threat_category = "Newly Registered Domain"
             else:
                 result.threat_category = "Social Engineering"
        elif has_mal:
            result.threat_type = "Malware"
            result.threat_category = "Payload/Dropper"
        else:
            result.threat_type = "Suspicious Activity"
            result.threat_category = "Anomalous Behavior"

    return result
