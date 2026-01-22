import email
from email import policy
import re

def parse_eml(content: bytes) -> dict:
    """
    Parses raw .eml bytes into a structured dictionary.
    """
    msg = email.message_from_bytes(content, policy=policy.default)
    
    # Extract body
    body_text = ""
    body_html = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get("Content-Disposition"))

            if ctype == "text/plain" and "attachment" not in cdispo:
                body_text += part.get_payload(decode=True).decode(errors="ignore")
            elif ctype == "text/html" and "attachment" not in cdispo:
                body_html += part.get_payload(decode=True).decode(errors="ignore")
    else:
        # Single part
        payload = msg.get_payload(decode=True).decode(errors="ignore")
        if msg.get_content_type() == "text/html":
            body_html = payload
        else:
            body_text = payload

    # Fallback: if no HTML, use text as source for analysis
    primary_body = body_html if body_html else body_text

    # Extract attachments (metadata only for now)
    attachments = []
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue
            
        filename = part.get_filename()
        if filename:
            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": len(part.get_payload(decode=True) or b""),
                "content": part.get_payload(decode=True) or b""
            })

    return {
        "headers": dict(msg.items()),
        "raw_headers": list(msg.items()), # Preserves order and duplicates
        "body_text": body_text,
        "body_html": body_html,
        "primary_body": primary_body,
        "attachments": attachments,
        "subject": msg.get("Subject", ""),
        "from": msg.get("From", ""),
        "to": msg.get("To", "")
    }
