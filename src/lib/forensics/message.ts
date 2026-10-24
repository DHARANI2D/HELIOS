import MsgReader from "@kenjiuno/msgreader";
import { simpleParser, type AddressObject, type ParsedMail } from "mailparser";

import type { HeaderLine } from "@/lib/forensics/headers";

// One parsed-message shape for both RFC 822 (.eml) and Outlook (.msg).
// Port of desas's eml_parser.py + msg_parser.py: .msg properties are often
// empty for mail that crossed several relays, so the transport-header block
// (PR_TRANSPORT_MESSAGE_HEADERS) is parsed too and used as the fallback —
// the same lesson desas's msg_parser documents.

export interface ParsedAttachment {
  filename: string;
  content: Uint8Array;
  contentType?: string;
  embeddedMessage?: boolean;
}

export interface ParsedMessage {
  format: "eml" | "msg";
  headerLines: HeaderLine[];
  subject: string;
  from?: string;
  to?: string;
  cc?: string;
  replyTo?: string;
  date?: Date;
  messageId?: string;
  text: string;
  html?: string;
  attachments: ParsedAttachment[];
}

function addressText(value: AddressObject | AddressObject[] | undefined): string | undefined {
  if (!value) return undefined;
  return (Array.isArray(value) ? value : [value]).map((v) => v.text).join(", ") || undefined;
}

function unfold(line: string): HeaderLine {
  const idx = line.indexOf(":");
  return { key: line.slice(0, idx).trim().toLowerCase(), value: line.slice(idx + 1).replace(/\r?\n[ \t]+/g, " ").trim() };
}

const CFB_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const MSG_STREAM_MARKER = Buffer.from("__substg1.0_", "utf16le");

// An Outlook item is a Compound File whose directory names its MAPI property
// streams "__substg1.0_XXXXYYYY" — that distinguishes it from a .doc/.xls.
export function isOutlookMsg(bytes: Uint8Array): boolean {
  if (bytes.length < 512 || !CFB_MAGIC.every((b, i) => bytes[i] === b)) return false;
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).includes(MSG_STREAM_MARKER);
}

export function looksLikeEml(filename: string, bytes: Uint8Array): boolean {
  if (/\.(eml|mht)$/i.test(filename)) return true;
  const head = Buffer.from(bytes.subarray(0, 4096)).toString("latin1");
  return /^(received|return-path|from|delivered-to|message-id|mime-version|subject|date|x-[\w-]+):/im.test(head) && /\r?\n\r?\n/.test(head);
}

async function fromMailparser(parsed: ParsedMail): Promise<Omit<ParsedMessage, "format">> {
  return {
    headerLines: parsed.headerLines.map((h) => unfold(h.line)),
    subject: parsed.subject ?? "(no subject)",
    from: addressText(parsed.from),
    to: addressText(parsed.to),
    cc: addressText(parsed.cc),
    replyTo: addressText(parsed.replyTo),
    date: parsed.date,
    messageId: parsed.messageId,
    text: parsed.text ?? "",
    html: typeof parsed.html === "string" ? parsed.html : undefined,
    attachments: parsed.attachments.map((a) => ({
      filename: a.filename ?? "unnamed",
      content: new Uint8Array(a.content),
      contentType: a.contentType,
      embeddedMessage: a.contentType === "message/rfc822",
    })),
  };
}

function parseMsg(bytes: Uint8Array): Promise<ParsedMessage> {
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  const reader = new MsgReader(buffer);
  const data = reader.getFileData();
  if (data.error) throw new Error(`Unreadable .msg file: ${data.error}`);

  return (async () => {
    // Transport headers are an RFC 822 header block; mailparser gives us
    // structured header lines and addresses from it for free.
    const transport = data.headers ? await simpleParser(`${data.headers.trim()}\r\n\r\n`) : undefined;
    const headers = transport ? await fromMailparser(transport) : undefined;

    const recipients = (type: "to" | "cc") =>
      (data.recipients ?? [])
        .filter((r) => (r.recipType ?? "to") === type)
        .map((r) => (r.name && r.smtpAddress ? `${r.name} <${r.smtpAddress}>` : r.smtpAddress ?? r.email ?? r.name))
        .filter(Boolean)
        .join(", ") || undefined;

    const senderAddress = data.senderSmtpAddress ?? (data.senderEmail?.includes("@") ? data.senderEmail : undefined);
    const sender = senderAddress ? (data.senderName ? `${data.senderName} <${senderAddress}>` : senderAddress) : data.senderName;

    const html =
      data.bodyHtml ??
      (data.html ? Buffer.from(data.html).toString("utf8") : undefined);

    const sent = data.clientSubmitTime ?? data.messageDeliveryTime ?? data.creationTime;
    const date = headers?.date ?? (sent ? new Date(sent) : undefined);

    const attachments: ParsedAttachment[] = (data.attachments ?? []).map((att) => {
      const file = reader.getAttachment(att);
      return {
        filename: file.fileName || att.fileName || att.fileNameShort || "unnamed.bin",
        content: file.content,
        contentType: att.attachMimeTag,
        embeddedMessage: att.innerMsgContent === true,
      };
    });

    // Prefer the header block (what the relays actually saw), fall back to
    // the MAPI properties, then synthesize minimal header lines so header
    // analysis still sees From / Subject.
    const headerLines: HeaderLine[] = headers?.headerLines.length
      ? headers.headerLines
      : [
          ...(sender ? [{ key: "from", value: sender }] : []),
          ...(data.subject ? [{ key: "subject", value: data.subject }] : []),
        ];

    return {
      format: "msg" as const,
      headerLines,
      subject: (data.subject || headers?.subject) ?? "(no subject)",
      from: headers?.from ?? sender,
      to: headers?.to ?? recipients("to"),
      cc: headers?.cc ?? recipients("cc"),
      replyTo: headers?.replyTo,
      date: date && !Number.isNaN(date.getTime()) ? date : undefined,
      messageId: headers?.messageId ?? data.messageId,
      text: data.body ?? "",
      html,
      attachments,
    };
  })();
}

// No Date header (common in .msg exports and hand-built lures): use the
// first relay's Received timestamp, the earliest point the mail was seen.
function receivedDate(lines: HeaderLine[]): Date | undefined {
  const received = lines.filter((l) => l.key === "received");
  const first = received[received.length - 1]?.value;
  if (!first?.includes(";")) return undefined;
  const d = new Date(first.slice(first.lastIndexOf(";") + 1).trim());
  return Number.isNaN(d.getTime()) ? undefined : d;
}

export async function parseMessage(filename: string, bytes: Uint8Array): Promise<ParsedMessage | null> {
  let message: ParsedMessage | null = null;
  if (isOutlookMsg(bytes)) {
    message = await parseMsg(bytes);
  } else if (looksLikeEml(filename, bytes)) {
    const parsed = await simpleParser(Buffer.from(bytes), { skipImageLinks: true });
    message = { format: "eml", ...(await fromMailparser(parsed)) };
  }
  if (message && !message.date) message.date = receivedDate(message.headerLines);
  return message;
}
