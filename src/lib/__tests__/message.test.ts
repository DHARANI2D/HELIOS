import { describe, expect, it } from "vitest";
import { burn } from "@kenjiuno/msgreader/lib/Burner";
import { TypeEnum } from "@kenjiuno/msgreader/lib/Reader";

import { isOutlookMsg, parseMessage } from "@/lib/forensics/message";
import { analyzeHeaders } from "@/lib/forensics/headers";

process.env.FORENSICS_DNS_LOOKUPS = "false";

// Builds a minimal Outlook .msg (a Compound File of MAPI property streams)
// with msgreader's own CFB writer, so the test doesn't depend on a binary
// fixture of unknown provenance.
function buildMsg(opts: { subject: string; body: string; transportHeaders?: string; senderSmtp?: string; attachment?: { name: string; data: string } }) {
  const utf16 = (s: string) => Array.from(Buffer.from(`${s}\0`, "utf16le"));
  const stream = (name: string, data: number[]) => ({ name, type: TypeEnum.DOCUMENT, binaryProvider: () => data, length: data.length });
  const entries: Array<Record<string, unknown>> = [
    { name: "Root Entry", type: TypeEnum.ROOT, length: 0, children: [] as number[] },
    stream("__properties_version1.0", new Array(32).fill(0)),
    stream("__substg1.0_0037001F", utf16(opts.subject)),
    stream("__substg1.0_1000001F", utf16(opts.body)),
  ];
  if (opts.transportHeaders) entries.push(stream("__substg1.0_007D001F", utf16(opts.transportHeaders)));
  if (opts.senderSmtp) entries.push(stream("__substg1.0_5D01001F", utf16(opts.senderSmtp)));
  if (opts.attachment) {
    const base = entries.length;
    entries.push(
      { name: "__attach_version1.0_#00000000", type: TypeEnum.DIRECTORY, length: 0, children: [base + 1, base + 2, base + 3] },
      stream("__properties_version1.0", new Array(16).fill(0)),
      stream("__substg1.0_3707001F", utf16(opts.attachment.name)),
      stream("__substg1.0_37010102", Array.from(Buffer.from(opts.attachment.data))),
    );
  }
  // Root's children: every top-level entry (attachment substreams belong to the attachment storage).
  const topLevel = entries.map((_, i) => i).filter((i) => i > 0 && !(opts.attachment && i > entries.length - 4));
  (entries[0] as { children: number[] }).children = topLevel;
  return burn(entries as never);
}

describe("Outlook .msg parsing", () => {
  const msg = buildMsg({
    subject: "Invoice overdue",
    body: "Please review https://pay-invoice.example.top/x",
    transportHeaders: [
      "Received: from relay.bad.example ([185.220.101.45]) by mx.corp.example; Tue, 20 Oct 2026 08:00:00 +0000",
      "Authentication-Results: mx.corp.example; spf=fail smtp.mailfrom=bad.example; dmarc=fail (p=reject)",
      'From: "Billing" <billing@vendor.example>',
      "Reply-To: collect@other.example",
      "To: jdoe@corp.example",
      "Subject: Invoice overdue",
      "Message-ID: <abc@vendor.example>",
    ].join("\r\n"),
    attachment: { name: "invoice.js", data: "eval(atob('ZG9jdW1lbnQ='))" },
  });

  it("recognizes Outlook items but not other compound files", () => {
    expect(isOutlookMsg(msg)).toBe(true);
    const plainCfb = new Uint8Array(1024);
    plainCfb.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    expect(isOutlookMsg(plainCfb)).toBe(false);
  });

  it("maps properties, transport headers, and attachments", async () => {
    const parsed = (await parseMessage("mail.msg", msg))!;
    expect(parsed.format).toBe("msg");
    expect(parsed.subject).toBe("Invoice overdue");
    expect(parsed.from).toContain("billing@vendor.example");
    expect(parsed.replyTo).toContain("collect@other.example");
    expect(parsed.messageId).toBe("<abc@vendor.example>");
    expect(parsed.date?.toISOString()).toBe("2026-10-20T08:00:00.000Z");
    expect(parsed.text).toContain("pay-invoice.example.top");
    expect(parsed.attachments).toHaveLength(1);
    expect(parsed.attachments[0].filename).toBe("invoice.js");
    expect(Buffer.from(parsed.attachments[0].content).toString()).toContain("eval(");

    const headers = await analyzeHeaders(parsed.headerLines, parsed.subject);
    expect(headers.auth.spf.status).toBe("fail");
    expect(headers.senderIp).toBe("185.220.101.45");
    expect(headers.reasons.join(" ")).toContain("Reply-To mismatch");
  });

  it("falls back to MAPI properties when there is no transport header block", async () => {
    const bare = buildMsg({ subject: "Hello", body: "hi", senderSmtp: "someone@corp.example" });
    const parsed = (await parseMessage("x.msg", bare))!;
    expect(parsed.subject).toBe("Hello");
    expect(parsed.from).toBe("someone@corp.example");
    expect(parsed.headerLines).toEqual(expect.arrayContaining([{ key: "from", value: "someone@corp.example" }]));
  });
});

describe(".eml parsing", () => {
  it("flags message/rfc822 attachments as embedded messages", async () => {
    const inner = "From: a@x.example\r\nSubject: inner\r\n\r\nclick http://inner.example.xyz/\r\n";
    const eml = [
      "From: b@y.example",
      "Subject: FW: inner",
      'Content-Type: multipart/mixed; boundary="z"',
      "",
      "--z",
      "Content-Type: text/plain",
      "",
      "see attached",
      "--z",
      'Content-Type: message/rfc822; name="fwd.eml"',
      'Content-Disposition: attachment; filename="fwd.eml"',
      "",
      inner,
      "--z--",
      "",
    ].join("\r\n");
    const parsed = (await parseMessage("outer.eml", new Uint8Array(Buffer.from(eml))))!;
    expect(parsed.format).toBe("eml");
    const att = parsed.attachments.find((a) => a.embeddedMessage);
    expect(att).toBeDefined();
    const nested = await parseMessage(att!.filename, att!.content);
    expect(nested?.subject).toBe("inner");
  });

  it("returns null for non-message files", async () => {
    expect(await parseMessage("photo.png", new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 0]))).toBeNull();
  });
});

describe("MxToolbox diagnostics", () => {
  it("parses monitor results and skips DKIM without a selector", async () => {
    const { queryMxToolbox } = await import("@/lib/forensics/mxtoolbox");
    const calls: string[] = [];
    const original = globalThis.fetch;
    process.env.MXTOOLBOX_API_KEY = "test-key";
    globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
      calls.push(String(url));
      expect((init?.headers as Record<string, string>).Authorization).toBe("test-key");
      const failed = String(url).includes("/blacklist/") ? [{ Name: "Spamhaus DBL", Info: "Listed" }] : [];
      return new Response(JSON.stringify({ Failed: failed, Passed: [{ Name: "ok" }], Information: [] }), { status: 200 });
    }) as typeof fetch;
    try {
      const result = (await queryMxToolbox("bad.example"))!;
      expect(result.blacklist).toMatchObject({ checked: true, passed: false });
      expect(result.blacklist.details[0]).toMatchObject({ name: "Spamhaus DBL", status: "FAIL", info: "Listed" });
      expect(result.spf.passed).toBe(true);
      expect(result.dkim.checked).toBe(false);
      expect(calls).toHaveLength(6);
      expect(await queryMxToolbox("not a domain")).toBeNull();
    } finally {
      globalThis.fetch = original;
      delete process.env.MXTOOLBOX_API_KEY;
    }
  });
});
