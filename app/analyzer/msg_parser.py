import extract_msg
import io

def parse_msg(file_content: bytes) -> dict:
    """
    Parses an Outlook .msg file and returns a structured dictionary compatible with the .eml parser.
    """
    msg = extract_msg.Message(io.BytesIO(file_content))
    
    # Extract Headers
    # .msg headers are less structured than .eml, often found in 'transport_headers'
    headers_dict = {}
    
    # Basic Properties
    headers_dict["Subject"] = msg.subject
    headers_dict["From"] = msg.sender
    headers_dict["To"] = msg.to
    headers_dict["Date"] = str(msg.date)
    headers_dict["Message-ID"] = msg.messageId

    # Try to get raw headers if available
    raw_headers = msg.header
    if raw_headers:
        # Simple parsing for other headers if needed
        # Often raw_headers is a key-value object in extract-msg
        for k, v in raw_headers.items():
            headers_dict[k] = v

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
        if isinstance(att, extract_msg.Attachment): # Skipping specialized types if any
            attachments.append({
                "filename": att.longFilename or att.shortFilename or "unknown",
                "content": att.data # bytes
            })

    # Close message
    msg.close()

    return {
        "headers": headers_dict,
        "primary_body": primary_body,
        "attachments": attachments,
        "raw_headers": list(raw_headers.items()) if raw_headers else [] # Convert to list of tuples
    }
