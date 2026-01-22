from app.core.schemas import AnalysisResult, NetworkRequest

def calculate_sandbox_score(result_obj: AnalysisResult) -> tuple[int, list[str], list[str]]:
    """
    Recalculates just the sandbox portion of the score.
    Returns: (score, reasons, blocking_recs)
    """
    score = 0
    reasons = []
    recs = []

    # Rule 1: Password field detected
    if "password_field_detected" in result_obj.dom_mutations:
        score += 40  # SOC Blueprint: High points for credential harvesting
        reasons.append("Sandbox: Password input field detected (Credential Harvesting)")
        recs.append(f"Block URL: {result_obj.expanded_url}")

    # Rule 2: Redirect chain length
    if len(result_obj.redirect_chain) > 2:
        score += 10
        reasons.append(f"Sandbox: Long redirect chain ({len(result_obj.redirect_chain)} hops)")
    
    # Rule 3: Content Heuristics
    if "login_keywords_detected" in result_obj.dom_mutations:
        score += 10
        reasons.append("Sandbox: Login-related keywords found in rendered page")

    # Rule 4: Data Exfiltration Check
    for req in result_obj.network_requests:
        if req.method == "POST":
            # Simplified check
            score += 20
            reasons.append(f"Sandbox: POST request detected (Potential Exfil to {req.domain})")
            recs.append(f"Block Domain: {req.domain}")

    # Block original URL if suspicious
    if score >= 20:
        recs.append(f"Block Entry URL: {result_obj.url}")

    return score, reasons, recs

def aggregate_verdict(result: AnalysisResult) -> AnalysisResult:
    """
    Combines Header, Body, and Sandbox scores into a final verdict.
    """
    # 1. Calculate Sandbox Score (since it comes in raw)
    sb_score, sb_reasons, sb_recs = calculate_sandbox_score(result)
    
    result.sandbox_score = sb_score
    result.sandbox_reasons = sb_reasons
    
    # 2. Total Score
    total_score = result.header_score + result.body_score + result.sandbox_score
    result.total_score = total_score
    
    # 3. Aggregate Reasons & Recommendations
    all_reasons = result.header_reasons + result.body_reasons + result.sandbox_reasons
    result.risk_reasons = all_reasons
    
    # Merge block recommendations
    current_recs = set(result.block_recommendations)
    for r in sb_recs:
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

    return result
