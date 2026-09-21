import extract_msg
import io
import logging

logger = logging.getLogger("uvicorn")


def parse_msg(file_content: bytes) -> dict:
    """
    Parses an Outlook .msg file and returns a structured dictionary compatible with the .eml parser.
    """
    msg = extract_msg.Message(io.BytesIO(file_content))

    # Extract Headers
    # .msg headers are less structured than .eml, often found in 'transport_headers'
    headers_dict = {}

    # Basic Properties. extract_msg's own properties can be None for plenty
    # of real-world .msg files (complex Exchange/Proofpoint relay chains) -
    # setting a dict key to None (instead of omitting it) defeats any later
    # `.get(key, "")` fallback, since that only kicks in for a *missing*
    # key, not a falsy value. Guard with `or ""` here.
    headers_dict["Subject"] = msg.subject or ""
    headers_dict["From"] = msg.sender or ""
    headers_dict["To"] = msg.to or ""
    headers_dict["Date"] = str(msg.date) if msg.date else ""
    headers_dict["Message-ID"] = msg.messageId or ""

    # Try to get raw headers if available. msg.header is a real
    # email.message.Message (extract_msg parses the raw transport header
    # block with policy.compat32 internally), so it's a reliable fallback
    # source when the library's own subject/sender/to properties come back
    # empty - the raw header text is often more complete for mail that
    # passed through several relays.
    raw_headers = msg.header
    if raw_headers:
        # Simple parsing for other headers if needed
        # Often raw_headers is a key-value object in extract-msg
        for k, v in raw_headers.items():
            headers_dict[k] = v or ""

        if not headers_dict["Subject"]:
            headers_dict["Subject"] = raw_headers.get("Subject", "") or ""
        if not headers_dict["From"]:
            headers_dict["From"] = raw_headers.get("From", "") or ""
        if not headers_dict["To"]:
            headers_dict["To"] = raw_headers.get("To", "") or ""

    if not headers_dict["Subject"] and not headers_dict["From"]:
        logger.warning("parse_msg: Subject/From both empty after all fallbacks - check the .msg's header stream")

    # Extract Body
    # Prefer HTML, fallback to Text
    body_html = msg.htmlBody
    body_text = msg.body
    
    primary_body = ""
    if body_html:
        # Convert HTML to string or use as is (downstream analysis handles html content)
        primary_body = body_html.decode('utf-8', errors='ignore') if isinstance(body_html, bytes) else body_html
    elif body_text:
        primary_body = body_text

    # Extract Attachments
    attachments = []
    for att in msg.attachments:
        filename = att.longFilename or att.shortFilename
        if not filename:
             filename = "unknown.bin"
        
        # Simplified data access
        content = att.data
        if content is None:
             content = b""

        # Check nested
        is_nested = filename.lower().endswith(".msg")

        attachments.append({
            "filename": filename,
            "content": content,
            "is_nested_msg": is_nested,
            "content_type": getattr(att, 'mimetype', 'application/octet-stream')
        })

    # Close message
    msg.close()

    return {
        "headers": headers_dict,
        "primary_body": primary_body,
        "attachments": attachments,
        "raw_headers": list(raw_headers.items()) if raw_headers else [],
        "subject": headers_dict.get("Subject") or "",
        "from": headers_dict.get("From") or "",
        "to": headers_dict.get("To") or ""
    }

def extract_attachments_to_dir(file_path: str, output_dir: str) -> list:
    """
    Extracts all attachments from a MSG file to a directory.
    Targeting user's specific logic for 100% fidelity.
    """
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    extracted_files = []
    
    try:
        msg = extract_msg.Message(file_path)
        
        # 1. Save standard attachments
        for attachment in msg.attachments:
            # logic: attachment.longestFilename or attachment.shortFilename
            # but we let the library handle saving mostly, just ensuring the name
            try:
                # User used: attachment.save(customPath=output_dir)
                # We replicate that.
                if hasattr(attachment, 'save'):
                    attachment.save(customPath=output_dir, extractEmbedded=True)
                    fname = attachment.longFilename or attachment.shortFilename or "unknown"
                    if not fname and isinstance(attachment, extract_msg.attachments.EmbeddedMsg):
                         fname = "Embedded Msg" # Library often names it automatically on save though
                    extracted_files.append(fname)
            except Exception as e:
                print(f"Failed to save specific attachment: {e}")

        msg.close()
        
        # Re-list directory to get exact saved names (safest way to know what happened)
        extracted_files = os.listdir(output_dir)
        
    except Exception as e:
        print(f"Extraction failed: {e}")
        
    return extracted_files
