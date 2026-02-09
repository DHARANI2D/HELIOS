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

    # Extract attachments (logic updated to use iter_attachments as requested)
    attachments = []
    
    # 1. Standard Attachments via iter_attachments()
    for part in msg.iter_attachments():
        filename = part.get_filename()
        content_type = part.get_content_type()
        
        # User Logic: "if not filename: continue" 
        # But we still want to support the "Proofpoint" wrapper case where the inner email might be unnamed initially
        # So we will try to name it if it looks like a message/rfc822
        
        if not filename:
            if content_type == "message/rfc822":
                try:
                    nested = part.get_payload(0) if part.is_multipart() else email.message_from_bytes(part.get_payload(decode=True))
                    subject = nested.get("Subject", "dropped_email")
                    safe_subject = re.sub(r'[\\/*?:"<>|]', "", subject).strip()[:50]
                    filename = f"{safe_subject}.eml" if safe_subject else "dropped_email.eml"
                except:
                    filename = "dropped_email.eml"
            else:
                 # If truly unnamed and not an email, we might skip it per user request "only files from attachment"
                 # checking if it has a content-disposition of attachment is a safe bet
                 disposition = str(part.get("Content-Disposition", ""))
                 if "attachment" not in disposition:
                     continue
                 filename = f"unnamed_attachment_{len(attachments)}.bin"

        # Safe decode
        payload = part.get_payload(decode=True) or b""

        attachments.append({
            "filename": filename,
            "content_type": content_type,
            "mail_content_type": content_type,
            "size": len(payload),
            "content": payload
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
