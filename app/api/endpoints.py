from fastapi import APIRouter, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
import logging
import tldextract

# Modular Analyzers
from app.analyzer.eml_parser import parse_eml
from app.analyzer.msg_parser import parse_msg # New parser
from app.analyzer.headers import analyze_headers
from app.analyzer.body import analyze_body
from app.sandbox.browser import Sandbox
from app.core.scoring import aggregate_verdict
from app.core.schemas import AnalysisResult, NetworkRequest, HeaderRequest, URLRequest, DomainRequest, IPRequest, ReportRequest

router = APIRouter()
sandbox = Sandbox()
logger = logging.getLogger("uvicorn")

def extract_quotas(vt_headers: dict = None, mx_headers: dict = None) -> dict:
    quotas = {}
    if vt_headers:
        v = {k.lower(): v for k, v in vt_headers.items()}
        for key in ["x-rate-limit-remaining-month", "x-rate-limit-limit-month", "x-rate-limit-remaining-day", "x-rate-limit-remaining-minute"]:
            if key in v: quotas[key.replace("x-rate-limit-", "").replace("-", "_")] = v[key]
    if mx_headers:
        m = {k.lower(): v for k, v in mx_headers.items()}
        if "x-mxtoolbox-quota-remaining" in m: quotas["mx_remaining"] = m["x-mxtoolbox-quota-remaining"]
        if "x-mxtoolbox-quota-max" in m: quotas["mx_limit"] = m["x-mxtoolbox-quota-max"]
    return quotas

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
        recipient=parsed_data.get("to", "Unknown"),
        date=parsed_data.get("headers", {}).get("Date", "Unknown"),
        url="",
        expanded_url="",
        redirect_chain=[],
        network_requests=[],
        dom_mutations=[],
        suspicious_domains=[]
    )

    # 2.5 Check for nested phishing email or forensic artifacts
    header_found_in_att = False
    header_filename = ""
    nested_msg = ""
    
    # Priority 1: Recursive Analysis ("potential phish")
    # Loop twice if needed: once for nested, then once for artifacts inside the (new) parsed_data
    for att in parsed_data.get("attachments", []):
        fname = att.get("filename", "").lower()
        if "potential phish" in fname:
            try:
                nested_content = att.get("content", b"")
                # Detect if it's an MSG based on flag or extension
                if att.get("is_nested_msg") or fname.endswith(".msg"):
                    new_parsed_data = parse_msg(nested_content)
                else:
                    new_parsed_data = parse_eml(nested_content)
                
                if new_parsed_data:
                    parsed_data = new_parsed_data
                    nested_msg = f"Analysis redirected to nested email: {fname}"
                    # Re-sync basic metadata for result object
                    result.subject = parsed_data.get("subject", "Unknown")
                    result.sender = parsed_data.get("from", "Unknown")
                    result.recipient = parsed_data.get("to", "Unknown")
                    result.date = parsed_data.get("headers", {}).get("Date", "Unknown")
                    break 
            except Exception as e:
                logger.warning(f"Failed to parse nested phish: {e}")

    # Priority 2: Forensic Fragments (Headers/Body)
    from app.analyzer.headers import parse_headers_from_text
    # Note: If we redirected, parsed_data["attachments"] now contains the INNER attachments
    for att in parsed_data.get("attachments", []):
        fname = att.get("filename", "").lower()
        
        # Header Override
        if not header_found_in_att and "header" in fname and (fname.endswith(".txt") or fname.endswith(".log")):
            try:
                header_text = att.get("content", b"").decode("utf-8", errors="ignore")
                att_headers, att_raw = parse_headers_from_text(header_text)
                if att_headers:
                    parsed_data["headers"] = att_headers
                    parsed_data["raw_headers"] = att_raw
                    header_found_in_att = True
                    header_filename = fname
            except Exception: pass
            
        # Body Override
        if "bodyhtml" in fname and (fname.endswith(".txt") or fname.endswith(".html")):
            try:
                body_text = att.get("content", b"").decode("utf-8", errors="ignore")
                if body_text.strip():
                    parsed_data["primary_body"] = body_text
                    # Also store HTML if it's explicitly provided as HTML
                    if fname.endswith(".html"):
                        parsed_data["primary_body_html"] = body_text
            except Exception: pass

    # Store HTML for PDF reporting
    result.primary_body_html = parsed_data.get("primary_body_html", parsed_data.get("primary_body", ""))

    # 3. Header Analysis
    h_score, h_reasons, dkim_selector, hops, auth_results = analyze_headers(parsed_data["headers"], parsed_data.get("raw_headers"))
    
    if nested_msg:
        h_reasons.insert(0, nested_msg)
    if header_found_in_att:
        h_reasons.insert(0, f"Analysis performed on headers attached as '{header_filename}'")
        h_score += 5 
        # Update result metadata to reflect new headers
        result.subject = parsed_data["headers"].get("Subject", result.subject)
        result.sender = parsed_data["headers"].get("From", result.sender)
        result.recipient = parsed_data["headers"].get("To", result.recipient)
        result.date = parsed_data["headers"].get("Date", result.date)
    
    result.header_score = h_score
    result.header_reasons = h_reasons
    result.hops = hops
    result.auth_results = auth_results
    
    # Pack Raw Headers for UI
    # Schema expects List[Dict], parser gives List[Tuple]
    raw_tuples = parsed_data.get("raw_headers", [])
    result.all_headers = [{"name": k, "value": str(v)} for k, v in raw_tuples]

    # 4. Body Analysis
    from app.core.whitelist_manager import get_whitelist
    dynamic_whitelist = get_whitelist()
    b_score, b_reasons, urls, susp_domains, skipped_whitelist, html_intel = analyze_body(parsed_data["primary_body"], whitelist=dynamic_whitelist)
    
    # Check Domain Age for suspicious domains (BLOCK LIST)
    from app.analyzer.body import check_url_intel
    
    # 1. Process all extracted URLs for VT highlights
    for url in urls:
        is_dom = False
        target = url
        try:
            ext = tldextract.extract(url)
            if not ext.suffix: is_dom = True 
        except: pass
        
        d_score, d_reason, d_age, d_intel, vt_h = await check_url_intel(url, is_domain=is_dom)
        result.api_quotas.update(extract_quotas(vt_headers=vt_h))
        if d_intel:
            result.url_intel[url] = d_intel
            if d_age is not None:
                result.domain_age_days[url] = d_age
        
        if d_score > 0:
            b_score += d_score
            b_reasons.append(d_reason)

    # 2. Process suspicious domains specifically (backwards compatibility for UI)
    for domain in susp_domains:
        if domain not in result.url_intel:
            d_score, d_reason, d_age, d_intel, vt_h = await check_url_intel(domain, is_domain=True)
            result.api_quotas.update(extract_quotas(vt_headers=vt_h))
            if d_age is not None:
                result.domain_age_days[domain] = d_age
            if d_intel:
                result.url_intel[domain] = d_intel
                result.dns_details[domain] = d_intel.get("records", []) # if any
            if d_score > 0:
                b_score += d_score
                b_reasons.append(d_reason)
            
    # Also check Whitelisted domains on VT (Override logic)
    for w_domain in skipped_whitelist:
        if w_domain not in result.url_intel:
            d_score, d_reason, d_age, d_intel, vt_h = await check_url_intel(w_domain, is_domain=True)
            result.api_quotas.update(extract_quotas(vt_headers=vt_h))
            if d_age is not None:
                result.domain_age_days[w_domain] = d_age
            if d_intel:
                result.url_intel[w_domain] = d_intel
            if d_score > 0:
                b_reasons.append(f"Whitelisted domain '{w_domain}' flagged by VT: {d_reason}")
                b_score += 5

    result.body_score = b_score
    result.body_reasons = b_reasons
    result.suspicious_domains = susp_domains
    result.whitelisted_domains = skipped_whitelist
    result.extracted_urls = urls
    result.html_analysis = html_intel
    
    # Add suspicious domains to block recs immediately
    for d in susp_domains:
        result.block_recommendations.append(f"Block Domain: {d}")
    
    # 5a. MxToolbox Integration (Optional)
    from app.analyzer.mxtoolbox import query_mxtoolbox_with_headers
    sender_email = parsed_data.get("from", "")
    if sender_email:
        start = sender_email.find("@")
        end = sender_email.find(">")
        if end == -1: end = len(sender_email)
        sender_domain = sender_email[start+1:end].strip()
        
        mx_result, mx_h = await query_mxtoolbox_with_headers(sender_domain, dkim_selector)
        result.mxtoolbox_analysis = mx_result
        result.api_quotas.update(extract_quotas(mx_headers=mx_h))
        
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

    # 6. IP Intelligence
    from app.analyzer.reputation import get_ip_intel
    unique_ips = {h["ip"] for h in hops if h["ip"] != "unknown"}
    for ip in unique_ips:
        intel = await get_ip_intel(ip)
        result.ip_intel[ip] = intel
        
        # Add to score if high abuse confidence
        if intel["abuse_score"] >= 50:
            result.header_score += 20
            result.header_reasons.append(f"Network Intel: Infrastructure IP {ip} flagged with {intel['abuse_score']}% abuse confidence")

    # 7. Final preparation for progressive response
    result.header_status = "complete"
    result.body_status = "complete"
    
    if urls:
        result.sandbox_status = "pending"
    else:
        result.sandbox_status = "complete"
        result.sandbox_reasons.append("No URLs found to detonate.")

    # 8. Final aggregated scoring (Initial pass without sandbox)
    final_result = aggregate_verdict(result)

    return final_result

@router.post("/analyze/header")
async def analyze_standalone_header(req: HeaderRequest):
    from app.analyzer.headers import parse_headers_from_text, analyze_headers
    try:
        h_dict, h_list = parse_headers_from_text(req.headers)
        h_score, h_reasons, dkim_selector, hops, auth_results = analyze_headers(h_dict, h_list)
        
        # IP Intel for standalone headers too
        from app.analyzer.reputation import get_ip_intel
        ip_intel = {}
        for h in hops:
            if h["ip"] != "unknown":
                ip_intel[h["ip"]] = await get_ip_intel(h["ip"])

        return {
            "score": h_score,
            "reasons": h_reasons,
            "hops": hops,
            "auth_results": auth_results,
            "ip_intel": ip_intel,
            "all_headers": [{"name": k, "value": str(v)} for k, v in h_list]
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Header analysis failed: {str(e)}")

@router.post("/analyze/url")
async def analyze_standalone_url(req: URLRequest):
    from app.core.scoring import calculate_sandbox_score
    try:
        raw_sb_result = await sandbox.analyze_url(req.url)
        
        # Calculate score for this specific detonation
        score, reasons, recs = calculate_sandbox_score(raw_sb_result)
        raw_sb_result.score = score
        raw_sb_result.reasons = reasons
        raw_sb_result.status = "complete"
        
        return raw_sb_result
    except Exception as e:
        logger.error(f"Standalone URL analysis failed: {e}")
        return SandboxResult(
            url=req.url,
            expanded_url=req.url,
            redirect_chain=[],
            reasons=[f"Sandbox Failed: {str(e)}"],
            status="error"
        )

@router.post("/analyze/domain")
async def analyze_standalone_domain(req: DomainRequest):
    from app.analyzer.body import check_domain_age
    from app.core.whitelist_manager import get_whitelist
    try:
        domain = req.domain.lower().strip()
        score, reason, age, intel, vt_h = await check_domain_age(domain)
        
        # Check static + dynamic whitelist
        from app.core.config import settings
        dynamic_whitelist = get_whitelist()
        effective_whitelist = set(settings.DOMAIN_WHITELIST) | set(dynamic_whitelist)
        
        is_whitelisted = False
        for wd in effective_whitelist:
            wd_l = wd.lower().strip()
            if domain == wd_l or domain.endswith("." + wd_l):
                is_whitelisted = True
                break
        
        res = {
            "domain": domain,
            "score": 0 if is_whitelisted else score,
            "reason": f"Domain whitelisted. (Original: {reason})" if is_whitelisted else reason,
            "age_days": age,
            "intel": intel,
            "whitelisted": is_whitelisted,
            "api_quotas": extract_quotas(vt_headers=vt_h)
        }
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Domain analysis failed: {str(e)}")

@router.post("/analyze/ip")
async def analyze_standalone_ip(req: IPRequest):
    from app.analyzer.reputation import get_ip_intel
    try:
        intel = await get_ip_intel(req.ip)
        return intel
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"IP analysis failed: {str(e)}")

@router.post("/report/ip")
async def report_abusive_ip(req: ReportRequest):
    from app.analyzer.abuseipdb import AbuseIPDBClient
    client = AbuseIPDBClient()
    try:
        res = await client.report_ip(req.ip, req.categories, req.comment)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to report IP: {str(e)}")

@router.post("/analyze/attachment")
async def analyze_standalone_attachment(file: UploadFile = File(...)):
    from app.analyzer.attachments import analyze_attachments
    try:
        content = await file.read()
        # Mock attachment structure for the analyzer
        att_list = [{"filename": file.filename, "content": content}]
        a_score, a_reasons, processed = await analyze_attachments(att_list)
        return {
            "score": a_score,
            "reasons": a_reasons,
            "attachment": processed[0] if processed else {}
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Attachment analysis failed: {str(e)}")
@router.post("/report/pdf")
async def generate_pdf_report(data: AnalysisResult):
    import os
    import hashlib
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
    from fastapi.responses import StreamingResponse
    
    # 1. Capture email screenshot if HTML is available
    screenshot_path = None
    if data.primary_body_html:
        url_hash = hashlib.md5(data.primary_body_html.encode()).hexdigest()[:8]
        screenshot_path = f"app/static/mail_view_{url_hash}.png"
        if not os.path.exists(screenshot_path):
            try:
                await sandbox.screenshot_html(data.primary_body_html, screenshot_path)
            except Exception as e:
                logger.error(f"Failed to capture email screenshot: {e}")
                screenshot_path = None

    # 2. Build PDF
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=24, spaceAfter=20, textColor=colors.HexColor("#2563eb"))
    verdict_color = colors.red if data.total_score >= 71 else (colors.orange if data.total_score >= 31 else colors.green)
    verdict_style = ParagraphStyle('VerdictStyle', parent=styles['Heading2'], fontSize=18, textColor=verdict_color, spaceAfter=10)
    label_style = ParagraphStyle('LabelStyle', parent=styles['Normal'], fontSize=10, textColor=colors.grey)
    value_style = ParagraphStyle('ValueStyle', parent=styles['Normal'], fontSize=11, spaceAfter=6, fontWeight='bold')
    
    elements = []
    
    # Header
    elements.append(Paragraph("Email Forensic Analysis Report", title_style))
    elements.append(Paragraph(f"Verdict: {data.verdict.upper()} (Score: {data.total_score})", verdict_style))
    elements.append(Spacer(1, 12))
    
    # Metadata Table
    meta_data = [
        [Paragraph("Subject:", label_style), Paragraph(data.subject, value_style)],
        [Paragraph("Sender:", label_style), Paragraph(data.sender, value_style)],
        [Paragraph("Recipient:", label_style), Paragraph(data.recipient, value_style)],
        [Paragraph("Date:", label_style), Paragraph(data.date, value_style)]
    ]
    t = Table(meta_data, colWidths=[80, 400])
    t.setStyle(TableStyle([('ALIGN', (0, 0), (-1, -1), 'LEFT'), ('VALIGN', (0, 0), (-1, -1), 'TOP')]))
    elements.append(t)
    elements.append(Spacer(1, 24))
    
    # Email Body Screenshot
    if screenshot_path and os.path.exists(screenshot_path):
        elements.append(Paragraph("Email Visual Evidence", styles['Heading3']))
        img = Image(screenshot_path, width=450, height=300, kind='proportional')
        elements.append(img)
        elements.append(Spacer(1, 24))

    # VirusTotal Section
    if data.url_intel:
        elements.append(Paragraph("VirusTotal Reputation Intelligence", styles['Heading3']))
        vt_data = [["Target URL / Domain", "VT Hits", "Age (Days)", "Risk"]]
        for target, intel in data.url_intel.items():
            if not isinstance(intel, dict): continue
            hits = intel.get("hits")
            if hits is None: hits = intel.get("malicious", 0)
            
            age = intel.get("age")
            if age is None: age = intel.get("age_days", "Unknown")
            
            risk = "CRITICAL" if (isinstance(hits, int) and hits > 5) else ("WARNING" if (isinstance(hits, int) and hits > 0) else "CLEAN")
            vt_data.append([Paragraph(target, styles['Normal']), str(hits), str(age), risk])
        
        if len(vt_data) > 1:
            t = Table(vt_data, colWidths=[200, 80, 100, 100])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 24))

    # IP Reputation Section
    if data.ip_intel:
        elements.append(Paragraph("IP Infrastructure Reputation", styles['Heading3']))
        ip_data = [["IP Address", "Abuse Score", "Country", "ISP"]]
        for ip, intel in data.ip_intel.items():
            if not isinstance(intel, dict): continue
            # Check nested or flat structure
            rep = intel.get("reputation", {}) if isinstance(intel.get("reputation"), dict) else {}
            score = intel.get("abuse_score")
            if score is None: score = rep.get("abuse_score", 0)
            
            country = intel.get("country_code")
            if country is None: country = intel.get("geo", {}).get("country", "??")
            
            isp = intel.get("isp")
            if isp is None: isp = rep.get("isp", "Unknown")
            
            # Ensure isp is never None for Paragraph
            isp_value = str(isp) if isp is not None else "Unknown"
            ip_data.append([ip, f"{score}%", country, Paragraph(isp_value, styles['Normal'])])
        
        if len(ip_data) > 1:
            t = Table(ip_data, colWidths=[100, 80, 80, 220])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 24))

    # MxToolbox Section
    if data.mxtoolbox_analysis:
        elements.append(Paragraph("MxToolbox Security Diagnostics", styles['Heading3']))
        mx_data = [["Test", "Status", "Details"]]
        
        # Flatten MxToolbox results
        for tool, result in data.mxtoolbox_analysis.items():
            if tool == "error": continue
            status = "PASS" if result.get("passed") else "FAIL"
            # Get first failure or first detail
            details = "N/A"
            if result.get("details"):
                details = result["details"][0].get("info", "No additional info")
            mx_data.append([tool.upper(), status, Paragraph(details, styles['Normal'])])
        
        if len(mx_data) > 1:
            t = Table(mx_data, colWidths=[100, 60, 320])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 24))

    # Indicators Breakdown
    elements.append(Paragraph("Forensic Indicators summary", styles['Heading3']))
    
    indicator_data = [["Category", "Details", "Risk Level"]]
    
    # Helper to map score to risk level string
    def get_risk(s):
        if s >= 50: return "CRITICAL"
        if s >= 20: return "HIGH"
        if s >= 10: return "MEDIUM"
        return "LOW"

    for r in data.header_reasons:
        indicator_data.append(["Header", Paragraph(r, styles['Normal']), get_risk(15)])
    for r in data.body_reasons:
        indicator_data.append(["Content", Paragraph(r, styles['Normal']), get_risk(15)])
    for att in data.attachments:
        indicator_data.append(["Attachment", f"{att.get('filename')} ({att.get('risk')})", get_risk(40 if att.get('risk') != 'Clean' else 0)])

    if len(indicator_data) > 1:
        t = Table(indicator_data, colWidths=[80, 320, 80])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("No significant indicators detected during parsing.", styles['Normal']))

    elements.append(PageBreak())

    # Sandbox Results
    if data.sandbox_results:
        elements.append(Paragraph("Sandbox Behavioral Forensics", styles['Heading2']))
        elements.append(Spacer(1, 12))
        
        for idx, sb in enumerate(data.sandbox_results):
            elements.append(Paragraph(f"Target URL #{idx+1}: {sb.url}", styles['Heading4']))
            elements.append(Paragraph(f"Score: {sb.score} | Status: {sb.status}", styles['Normal']))
            
            if sb.reasons:
                elements.append(Paragraph("Behaviors Observed:", styles['Normal']))
                for r in sb.reasons:
                    elements.append(Paragraph(f"• {r}", styles['Normal']))
            
            if sb.screenshot_path and os.path.exists(f"app/{sb.screenshot_path}"):
                elements.append(Spacer(1, 12))
                img = Image(f"app/{sb.screenshot_path}", width=400, height=225, kind='proportional')
                elements.append(img)
            
            elements.append(Spacer(1, 24))

    # Build and Return
    try:
        doc.build(elements)
    except Exception as e:
        logger.error(f"PDF Build Error: {e}")
        # Build a failsafe report if complex elements failed
        elements = [Paragraph("Email Analysis Report (Recovery Mode)", title_style), Paragraph(f"An error occurred during detailed PDF generation: {str(e)}", styles['Normal'])]
        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        doc.build(elements)

    buf.seek(0)
    
    filename = f"desas_report_{hashlib.md5((data.subject or 'report').encode()).hexdigest()[:8]}.pdf"
    headers = {
        'Content-Disposition': f'attachment; filename="{filename}"'
    }
    return StreamingResponse(buf, media_type="application/pdf", headers=headers)
