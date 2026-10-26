import nodemailer from "nodemailer";

import { platformSecret } from "@/lib/platform-secrets";
import { getSetting } from "@/lib/settings";

// Outgoing email over the MSSP's own SMTP server: regulatory reports, breach
// notices and alerts. The server is a URL (smtps://user:password@host:465 or
// smtp://…:587 with STARTTLS), saved sealed under Settings or set in
// HELIOS_SMTP_URL; the sender is HELIOS_MAIL_FROM, else the company profile's
// email. Attachments are in-memory only: the transport may not read files or
// fetch URLs, so a message can't be made to carry something off the server.

export interface MailAttachment {
  filename: string;
  content: Buffer;
  contentType: string;
}

export interface MailInput {
  to: string[];
  cc?: string[];
  replyTo?: string;
  subject: string;
  text: string;
  attachments?: MailAttachment[];
}

export interface MailResult {
  messageId: string;
  accepted: string[];
  rejected: string[];
}

async function sender(): Promise<string | null> {
  if (process.env.HELIOS_MAIL_FROM) return process.env.HELIOS_MAIL_FROM;
  const company = await getSetting("company.profile").catch(() => null);
  if (!company?.email) return null;
  return company.name ? `"${company.name.replace(/"/g, "")}" <${company.email}>` : company.email;
}

export async function mailStatus(): Promise<{ configured: boolean; from: string | null; reason?: string }> {
  const [url, from] = await Promise.all([platformSecret("smtp"), sender()]);
  if (!url) return { configured: false, from, reason: "No outgoing mail server is set (Settings → provider keys, or HELIOS_SMTP_URL)" };
  if (!from) return { configured: false, from, reason: "No sender address: set HELIOS_MAIL_FROM or the company email in Settings" };
  return { configured: true, from };
}

const plain = (list: string[] | undefined) => (list ?? []).map((a) => a.trim()).filter(Boolean);

export async function sendMail(input: MailInput): Promise<MailResult> {
  const url = await platformSecret("smtp");
  const from = await sender();
  if (!url || !from) throw new Error((await mailStatus()).reason ?? "Outgoing mail isn't set up");
  const transport = nodemailer.createTransport(url, { disableFileAccess: true, disableUrlAccess: true });
  try {
    const info = await transport.sendMail({
      from,
      to: plain(input.to),
      cc: plain(input.cc),
      replyTo: input.replyTo || undefined,
      subject: input.subject.replace(/[\r\n]+/g, " ").slice(0, 250),
      text: input.text,
      attachments: (input.attachments ?? []).map((a) => ({ filename: a.filename, content: a.content, contentType: a.contentType })),
    });
    const addr = (x: unknown) => (typeof x === "string" ? x : ((x as { address?: string })?.address ?? ""));
    return { messageId: info.messageId, accepted: (info.accepted ?? []).map(addr), rejected: (info.rejected ?? []).map(addr) };
  } finally {
    transport.close();
  }
}
