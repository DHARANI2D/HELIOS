
import email
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import os

def create_wrapper_sample():
    # 1. Create a dummy inner "malicious" email if not exists
    inner_eml_path = "samples/inner_malicious.eml"
    if not os.path.exists(inner_eml_path):
        msg = EmailMessage()
        msg["Subject"] = "Urgent: Invoice Overdue"
        msg["From"] = "attacker@bad.com"
        msg["To"] = "victim@company.com"
        msg.set_content("Please pay the attached invoice immediately. http://phishing-site.com/login")
        with open(inner_eml_path, "wb") as f:
            f.write(msg.as_bytes())
        print(f"Created inner sample: {inner_eml_path}")

    # 2. Create the wrapper email (e.g. Proofpoint Report)
    wrapper = MIMEMultipart()
    wrapper["Subject"] = "Proofpoint: Suspicious Email Quarantine"
    wrapper["From"] = "reports@proofpoint.com"
    wrapper["To"] = "admin@company.com"
    
    body = """
    The attached email was quarantined due to suspicious content.
    Please review the attachment.
    """
    wrapper.attach(MIMEText(body, "plain"))
    
    # 3. Attach the inner email
    with open(inner_eml_path, "rb") as f:
        inner_content = f.read()
        
    # Attach as message/rfc822 or just application/octet-stream with .eml extension
    part = MIMEApplication(inner_content, Name="quarantined_mail.eml")
    part['Content-Disposition'] = 'attachment; filename="quarantined_mail.eml"'
    wrapper.attach(part)
    
    output_path = "samples/wrapper_sample.eml"
    with open(output_path, "wb") as f:
        f.write(wrapper.as_bytes())
        
    print(f"Created wrapper sample: {output_path}")

if __name__ == "__main__":
    if not os.path.exists("samples"):
        os.makedirs("samples")
    create_wrapper_sample()
