from fastapi import APIRouter, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
import logging

# Modular Analyzers
from app.analyzer.eml_parser import parse_eml
from app.analyzer.msg_parser import parse_msg # New parser
from app.analyzer.headers import analyze_headers
from app.analyzer.body import analyze_body
from app.sandbox.browser import Sandbox
from app.core.scoring import aggregate_verdict
from app.core.schemas import AnalysisResult, NetworkRequest

router = APIRouter()
sandbox = Sandbox()
logger = logging.getLogger("uvicorn")

@router.post("/test")
async def test_upload(file: UploadFile = File(...)):
    return {"filename": file.filename, "content_type": file.content_type}

@router.post("/analyze/email")
async def analyze_email_api(file: UploadFile = File(...)):
    # 1. Parse File
    try:
        content = await file.read()
        filename = file.filename.lower()
        
        if filename.endswith('.msg') or file.content_type == 'application/vnd.ms-outlook':
            parsed_data = parse_msg(content)
        else:
            parsed_data = parse_eml(content)
            
    except Exception as e:
        logger.error(f"Error parsing EML: {e}")
        raise HTTPException(status_code=400, detail="Invalid .eml file structure")

    # 2. Initialize Result Object
    result = AnalysisResult(
        subject=parsed_data.get("subject", "Unknown"),
        sender=parsed_data.get("from", "Unknown"),
        url="",
        expanded_url="",
        redirect_chain=[],
        network_requests=[],
        dom_mutations=[],
        suspicious_domains=[]
    )

    # 3. Header Analysis
    h_score, h_reasons, dkim_selector, hops, auth_results = analyze_headers(parsed_data["headers"], parsed_data.get("raw_headers"))
    result.header_score = h_score
    result.header_reasons = h_reasons
    result.hops = hops
    result.auth_results = auth_results
    
    # Pack Raw Headers for UI
    # Schema expects List[Dict], parser gives List[Tuple]
    raw_tuples = parsed_data.get("raw_headers", [])
    result.all_headers = [{"name": k, "value": str(v)} for k, v in raw_tuples]

    # 4. Body Analysis
    # Note: analyze_body is sync, check_domain_age is async
    # Now returns 5 values including whitelisted_hits
    b_score, b_reasons, urls, susp_domains, skipped_whitelist = analyze_body(parsed_data["primary_body"])
    
    # Check Domain Age for suspicious domains (BLOCK LIST)
    from app.analyzer.body import check_domain_age
    for domain in susp_domains:
        d_score, d_reason = await check_domain_age(domain)
        if d_score > 0:
            b_score += d_score
            b_reasons.append(d_reason)
            
    # Also check Whitelisted domains on VT (Override logic)
    # If VT finds them suspicious (e.g. young), we flag them but maybe with less/different score?
    # Or just report them.
    for w_domain in skipped_whitelist:
        # We still want to know if they are young/suspicious contextually
        d_score, d_reason = await check_domain_age(w_domain)
        if d_score > 0:
            # It's whitelisted but VT says it's young/bad?
            # We add a specific warning reason but DO NOT add to block list recommended immediately
            b_reasons.append(f"Whitelisted domain '{w_domain}' flagged by VT: {d_reason}")
            # Optional: Add small score penalty?
            b_score += 5

    result.body_score = b_score
    result.body_reasons = b_reasons
    result.suspicious_domains = susp_domains
    result.whitelisted_domains = skipped_whitelist
    result.extracted_urls = urls
    
    # Add suspicious domains to block recs immediately
    for d in susp_domains:
        result.block_recommendations.append(f"Block Domain: {d}")
    
    # 5a. MxToolbox Integration (Optional)
    from app.analyzer.mxtoolbox import query_mxtoolbox
    sender_email = parsed_data.get("from", "")
    if sender_email:
        start = sender_email.find("@")
        end = sender_email.find(">")
        if end == -1: end = len(sender_email)
        sender_domain = sender_email[start+1:end].strip()
        
        # Async call - catch errors inside query_mxtoolbox logic wrapper if not robust
        # But we made it robust.
        mx_result = await query_mxtoolbox(sender_domain, dkim_selector)
        result.mxtoolbox_analysis = mx_result
        
        # Add to score if blacklisted
        if mx_result.get("blacklist", {}).get("passed") is False:
             result.header_score += 50
             result.header_reasons.append(f"MxToolbox: Domain {sender_domain} is on BLACKLIST")

    # 5b. Attachment Analysis
    from app.analyzer.attachments import analyze_attachments
    if parsed_data.get("attachments"):
        a_score, a_reasons, processed_attachments = await analyze_attachments(parsed_data["attachments"])
        # Add to body score for now as "Content" risk, or separate if UI supports it. 
        # For this version, we'll add to body score but track reasons clearly
        result.body_score += a_score
        result.body_reasons.extend(a_reasons)
        result.attachments = processed_attachments

    # 6. Dynamic Sandbox (if URL exists)
    if urls:
        target_url = urls[0] # Prototype: Analyze first URL
        result.url = target_url
        
        # Run Sandbox
        try:
            raw_sb_result = await sandbox.analyze_url(target_url)
            
            # Merge Sandbox Data into Main Result
            result.expanded_url = raw_sb_result.expanded_url
            result.redirect_chain = raw_sb_result.redirect_chain
            result.screenshot_path = raw_sb_result.screenshot_path
            result.network_requests = raw_sb_result.network_requests
            result.dom_mutations = raw_sb_result.dom_mutations
            
        except Exception as e:
            logger.error(f"Sandbox failed: {e}")
            result.sandbox_reasons.append(f"Sandbox Analysis Failed: {str(e)}")
    else:
        result.sandbox_reasons.append("No URLs found to detonate.")

    # 7. Final aggregated scoring
    final_result = aggregate_verdict(result)

    return final_result
