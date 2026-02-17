import os
import json
from datetime import datetime

def generate_html_report(data: dict) -> str:
    """Generates a standalone, styled HTML report from AnalysisResult data."""
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Extract data for easier access
    subject = data.get("subject", "No Subject")
    sender = data.get("sender", "Unknown")
    recipient = data.get("recipient", "Unknown")
    date = data.get("date", "Unknown")
    verdict = data.get("verdict", "Unknown")
    score = data.get("score", 0)
    reasons = data.get("reasons", [])
    
    # Intelligence Table data
    domains = data.get("suspicious_domains", [])
    urls = data.get("extracted_urls", [])
    whitelisted = data.get("whitelisted_domains", [])
    url_intel = data.get("url_intel", {})
    
    intel_rows = ""
    all_artifacts = [
        *[( 'DOMAIN', d) for d in domains],
        *[( 'URL', u) for u in urls],
        *[( 'WHITELISTED', w) for w in whitelisted]
    ]
    
    for type_label, val in all_artifacts:
        intel = url_intel.get(val, {})
        hits = intel.get("hits", 0)
        color = "#ef4444" if hits > 0 else ("#22c55e" if type_label == 'WHITELISTED' else "#64748b")
        age = f"{intel.get('age')}d" if intel.get('age') is not None else "-"
        registrar = intel.get("registrar", "-")
        cats = ", ".join(intel.get("categories", [])[:3]) or "-"
        tags = ", ".join(intel.get("tags", [])[:3]) or "-"
        
        intel_rows += f"""
        <tr style="background: {'#fef2f2' if hits > 0 else 'white'};">
            <td><span style="font-size:10px; font-weight:bold; color:#64748b;">{type_label}</span></td>
            <td style="word-break:break-all;"><b>{val}</b></td>
            <td style="color:{color}; font-weight:bold;">{hits}</td>
            <td>{registrar} / {age}</td>
            <td style="font-size:11px;">{cats}<br><small>{tags}</small></td>
        </tr>
        """

    # Forensics (Hops & Headers)
    all_headers = data.get("all_headers", [])
    headers_html = "\n".join([f"<div><b>{h['name']}:</b> {h['value']}</div>" for h in all_headers]) or "No headers recorded."
    
    hops = data.get("hops", [])
    hops_rows = "".join([f"<tr><td>#{h['hop']}</td><td>{h['delay']}</td><td>{h['from']}<br><small>{h['ip']}</small></td><td>{h['time']}</td></tr>" for h in hops])
    if not hops_rows:
        hops_rows = '<tr><td colspan="4" style="text-align:center; padding:20px;">No routing hops detected.</td></tr>'

    # Sandbox Results
    import base64 as b6
    sandbox_results = data.get("sandbox_results", [])
    sandbox_findings = ""
    for i, res in enumerate(sandbox_results):
        r_score = res.get("score", 0)
        r_color = "#ef4444" if r_score > 70 else ("#f59e0b" if r_score > 30 else "#22c55e")
        reasons_list = "".join([f"<li>{r}</li>" for r in res.get("reasons", [])])
        
        # Try to embed screenshot if it exists on disk
        screenshot_embed = ""
        s_path = res.get("screenshot_path")
        if s_path:
            full_path = os.path.join("app", "static", s_path)
            if os.path.exists(full_path):
                with open(full_path, "rb") as f:
                    b64_img = b6.b64encode(f.read()).decode('utf-8')
                    screenshot_embed = f'<img src="data:image/png;base64,{b64_img}" style="width:100%; border-radius:8px; border:1px solid #ddd; margin-top:12px;">'
        
        if not screenshot_embed:
            screenshot_embed = f'<div style="padding:20px; text-align:center; background:#f1f5f9; border-radius:8px; font-size:12px; color:#64748b; margin-top:12px;">No screenshot captured or available in bundle.</div>'

        sandbox_findings += f"""
        <div style="margin-bottom: 32px; padding: 24px; border: 1px solid #e2e8f0; border-radius: 12px; background:white;">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:16px;">
                <div>
                    <h3 style="margin:0; font-size:18px; color:#1e293b;">🌐 Detonation: {res.get('url')}</h3>
                    <p style="margin:4px 0; font-size:12px; color:#64748b;">Target URL analyzed in Isolated Sandbox</p>
                </div>
                <span style="background:{r_color}; color:white; padding:6px 16px; border-radius:8px; font-weight:800; font-size:14px;">{r_score} / 100</span>
            </div>
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:24px;">
                <div>
                    <h4 style="font-size:12px; text-transform:uppercase; color:#64748b; border-bottom:1px solid #eee; padding-bottom:4px;">Behavioral Indicators</h4>
                    <ul style="padding-left:20px; margin-top:12px; font-size:13px; color:#334155;">{reasons_list or "<li>No suspicious behavioral indicators recorded.</li>"}</ul>
                </div>
                <div>
                    <h4 style="font-size:12px; text-transform:uppercase; color:#64748b; border-bottom:1px solid #eee; padding-bottom:4px;">Visual Evidence</h4>
                    {screenshot_embed}
                </div>
            </div>
        </div>
        """

    if not intel_rows:
        intel_rows = '<tr><td colspan="5" style="text-align:center; padding:32px; color:#64748b;">No artifacts identified.</td></tr>'

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>DESAS Forensic Report - {subject}</title>
        <style>
            :root {{
                --primary: #2563eb;
                --danger: #ef4444;
                --success: #22c55e;
                --text: #1e293b;
                --bg: #f8fafc;
            }}
            body {{ font-family: 'Segoe UI', system-ui; color: var(--text); background: var(--bg); line-height: 1.5; padding: 40px; }}
            .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
            .header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 30px; }}
            .verdict-badge {{ padding: 12px 24px; border-radius: 8px; font-weight: 800; text-transform: uppercase; color: white; }}
            .verdict-malicious {{ background: var(--danger); }}
            .verdict-suspicious {{ background: #f59e0b; }}
            .verdict-clean {{ background: var(--success); }}
            
            h1 {{ margin: 0; font-size: 24px; color: var(--primary); }}
            h2 {{ font-size: 18px; margin-top: 30px; border-left: 4px solid var(--primary); padding-left: 12px; margin-bottom: 16px; }}
            
            .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; background: #f1f5f9; padding: 20px; border-radius: 8px; }}
            .meta-item b {{ color: #64748b; font-size: 12px; display: block; }}
            
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th {{ text-align: left; padding: 12px; background: #f1f5f9; font-size: 12px; color: #64748b; }}
            td {{ padding: 12px; border-bottom: 1px solid #e2e8f0; font-size: 14px; }}
            
            .reasons-list {{ margin-top: 10px; }}
            .reasons-list li {{ color: var(--danger); font-weight: 600; margin-bottom: 8px; }}
            
            .tech-headers {{ background: #1e293b; color: #cbd5e1; padding: 20px; border-radius: 8px; font-family: monospace; font-size: 11px; max-height: 400px; overflow-y: auto; white-space: pre-wrap; }}
            
            @media print {{
                body {{ padding: 0; background: white; }}
                .container {{ box-shadow: none; max-width: 100%; }}
                .no-print {{ display: none; }}
            }}
            .footer {{ margin-top: 50px; text-align: center; color: #94a3b8; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div>
                    <h1>DESAS Forensic Analysis</h1>
                    <p style="margin: 4px 0; color: #64748b;">Generated on {timestamp}</p>
                </div>
                <div class="verdict-badge verdict-{verdict.lower()}">
                    {verdict} Report
                </div>
            </div>

            <div class="meta-grid">
                <div class="meta-item"><b>Subject</b> {subject}</div>
                <div class="meta-item"><b>Date</b> {date}</div>
                <div class="meta-item"><b>From</b> {sender}</div>
                <div class="meta-item"><b>To</b> {recipient}</div>
            </div>

            <h2>Analysis Findings</h2>
            <ul class="reasons-list">
                { "".join([f"<li>⚠️ {r}</li>" for r in reasons]) or "<li>✅ No suspicious patterns detected in heuristics.</li>" }
            </ul>

            <h2>Intelligence Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>TYPE</th>
                        <th>ARTIFACT</th>
                        <th>VT HITS</th>
                        <th>REGISTRAR / AGE</th>
                        <th>CATEGORIES / TAGS</th>
                    </tr>
                </thead>
                <tbody>
                    {intel_rows}
                </tbody>
            </table>

            <h2>Sandbox Detonation Results</h2>
            {sandbox_findings or '<p style="text-align:center; padding:32px; color:#64748b; background:#f1f5f9; border-radius:12px;">No URLs selected for sandbox detonation.</p>'}

            <h2>Routing Infrastructure</h2>
            <table>
                <thead>
                    <tr>
                        <th>HOP</th>
                        <th>DELAY</th>
                        <th>SOURCE / IP</th>
                        <th>TIMESTAMP</th>
                    </tr>
                </thead>
                <tbody>
                    {hops_rows}
                </tbody>
            </table>

            <h2>Forensic Technical Headers</h2>
            <div class="tech-headers">{headers_html}</div>

            <div class="footer">
                DESAS Cyber-Workstation | Open-Source Forensic Toolkit
            </div>
        </div>
    </body>
    </html>
    """
    return html
    return html
