import { simpleParser } from "mailparser";

// Ported from desas's analyzer/eml_parser.py parse_eml. Uses mailparser's
// raw `headerLines` (original unparsed text) rather than its structurally
// parsed header objects, for the same reason the Python version falls back
// to the lenient compat32 policy: real-world corporate mail routinely
// violates strict RFC 5322 parsing, and header analysis here works off
// regex over raw header text anyway.

export interface ParsedAttachment {
  filename: string;
  contentType: string;
  size: number;
  content: Buffer;
}

export interface ParsedEmail {
  headers: Record<string, string[]>;
  bodyText: string;
  bodyHtml: string;
  primaryBody: string;
  attachments: ParsedAttachment[];
  subject: string;
  from: string;
  to: string;
}

export async function parseEml(content: Buffer): Promise<ParsedEmail> {
  const parsed = await simpleParser(content);

  const headers: Record<string, string[]> = {};
  for (const { key, line } of parsed.headerLines) {
    const value = line.slice(line.indexOf(":") + 1).trim();
    (headers[key.toLowerCase()] ??= []).push(value);
  }

  const bodyText = parsed.text ?? "";
  const bodyHtml = parsed.html || "";
  const primaryBody = bodyHtml || bodyText;

  const attachments: ParsedAttachment[] = parsed.attachments.map((a) => ({
    filename: a.filename ?? `unnamed_attachment.bin`,
    contentType: a.contentType,
    size: a.size,
    content: a.content,
  }));

  const subject = parsed.subject ?? "";
  const from = parsed.from?.text ?? headers["from"]?.[0] ?? "";
  const to = Array.isArray(parsed.to) ? parsed.to.map((t) => t.text).join(", ") : parsed.to?.text ?? "";

  return { headers, bodyText, bodyHtml, primaryBody, attachments, subject, from, to };
}
