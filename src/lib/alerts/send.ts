import { createHmac } from "node:crypto";

import { platformSecret } from "@/lib/platform-secrets";
import { getSetting, type MessagingSettings } from "@/lib/settings";
import { mailStatus, sendMail } from "@/lib/mail";
import { smsText, type AlertChannel } from "@/lib/alerts/kinds";

// Sending one alert now, over one channel. Email goes through lib/mail; SMS
// and WhatsApp through Twilio's Messages API or a signed webhook to any
// other gateway (signed like every HELIOS webhook: HMAC-SHA256 over
// "<timestamp>.<body>"). Every result says whether a retry could help.

export interface AlertMessage {
  id?: string;
  subject: string;
  body?: string | null;
  link?: string | null;
}

export interface SendResult {
  ok: boolean;
  providerRef?: string;
  error?: string;
  // A retry won't help (a bad number, rejected credentials, nothing set up).
  permanent?: boolean;
}

const TWILIO_API = () => (process.env.HELIOS_TWILIO_API ?? "https://api.twilio.com").replace(/\/+$/, "");

export async function channelStatus(): Promise<Record<AlertChannel, { ready: boolean; reason?: string }>> {
  const [mail, messaging, twilio, hook] = await Promise.all([mailStatus(), getSetting("alerts.messaging"), platformSecret("twilio"), platformSecret("alertWebhook")]);
  const phone = (whatsapp: boolean) => {
    if (messaging.provider === "none") return { ready: false, reason: "No SMS or WhatsApp provider is set (Settings → Alert channels)" };
    if (messaging.provider === "twilio" && !twilio) return { ready: false, reason: "The Twilio account isn't saved (Settings → provider keys)" };
    if (messaging.provider === "webhook" && (!messaging.webhookUrl || !hook)) return { ready: false, reason: "The gateway URL or its signing secret isn't set" };
    if (messaging.provider === "twilio" && !(whatsapp ? messaging.whatsappFrom : messaging.smsFrom)) return { ready: false, reason: `No ${whatsapp ? "WhatsApp" : "SMS"} sender number is set` };
    return { ready: true };
  };
  return { email: mail.configured ? { ready: true } : { ready: false, reason: mail.reason }, sms: phone(false), whatsapp: phone(true) };
}

const transient = (status: number) => status === 408 || status === 429 || status >= 500;

async function twilio(m: MessagingSettings, channel: "sms" | "whatsapp", to: string, msg: AlertMessage): Promise<SendResult> {
  const cred = await platformSecret("twilio");
  if (!cred) return { ok: false, error: "The Twilio account isn't saved", permanent: true };
  const [sid, token] = [cred.slice(0, cred.indexOf(":")), cred.slice(cred.indexOf(":") + 1)];
  const whatsapp = channel === "whatsapp";
  const from = whatsapp ? m.whatsappFrom : m.smsFrom;
  if (!from) return { ok: false, error: `No ${whatsapp ? "WhatsApp" : "SMS"} sender number is set`, permanent: true };
  const form = new URLSearchParams({ To: whatsapp ? `whatsapp:${to}` : to, From: whatsapp ? `whatsapp:${from}` : from });
  if (whatsapp && m.whatsappTemplate) {
    form.set("ContentSid", m.whatsappTemplate);
    form.set("ContentVariables", JSON.stringify({ 1: msg.subject.slice(0, 200), 2: msg.link ?? "" }));
  } else {
    form.set("Body", smsText(msg.subject, msg.body, msg.link ?? null));
  }
  try {
    const res = await fetch(`${TWILIO_API()}/2010-04-01/Accounts/${encodeURIComponent(sid)}/Messages.json`, {
      method: "POST",
      headers: { authorization: `Basic ${Buffer.from(`${sid}:${token}`).toString("base64")}`, "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
      signal: AbortSignal.timeout(15_000),
    });
    const data = (await res.json().catch(() => ({}))) as { sid?: string; message?: string; code?: number };
    if (res.ok && data.sid) return { ok: true, providerRef: data.sid };
    return { ok: false, error: `Twilio ${res.status}${data.code ? ` (${data.code})` : ""}: ${data.message ?? "rejected"}`, permanent: !transient(res.status) };
  } catch (err) {
    return { ok: false, error: `Twilio unreachable: ${err instanceof Error ? err.message : String(err)}` };
  }
}

async function gateway(m: MessagingSettings, channel: "sms" | "whatsapp", to: string, msg: AlertMessage): Promise<SendResult> {
  const secret = await platformSecret("alertWebhook");
  if (!m.webhookUrl || !secret) return { ok: false, error: "The gateway URL or its signing secret isn't set", permanent: true };
  const body = JSON.stringify({ id: msg.id ?? null, channel, to, text: smsText(msg.subject, msg.body, msg.link ?? null), subject: msg.subject, link: msg.link ?? null });
  const ts = String(Math.floor(Date.now() / 1000));
  try {
    const res = await fetch(m.webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json", "x-helios-timestamp": ts, "x-helios-signature": `sha256=${createHmac("sha256", secret).update(`${ts}.${body}`).digest("hex")}` },
      body,
      signal: AbortSignal.timeout(15_000),
    });
    if (res.ok) return { ok: true, providerRef: res.headers.get("x-message-id") ?? undefined };
    return { ok: false, error: `Gateway answered ${res.status}`, permanent: !transient(res.status) };
  } catch (err) {
    return { ok: false, error: `Gateway unreachable: ${err instanceof Error ? err.message : String(err)}` };
  }
}

export async function sendAlert(channel: AlertChannel, to: string, msg: AlertMessage): Promise<SendResult> {
  if (channel === "email") {
    const status = await mailStatus();
    if (!status.configured) return { ok: false, error: status.reason, permanent: true };
    try {
      const text = [msg.subject, msg.body, msg.link ? `Open in HELIOS: ${msg.link}` : null, "", `Change which alerts you get: ${process.env.AUTH_URL ?? ""}/account/alerts`].filter((l) => l !== null && l !== undefined).join("\n");
      const r = await sendMail({ to: [to], subject: `[HELIOS] ${msg.subject}`, text });
      return r.accepted.length ? { ok: true, providerRef: r.messageId } : { ok: false, error: `The mail server refused ${to}`, permanent: true };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  }
  const m = await getSetting("alerts.messaging");
  if (m.provider === "twilio") return twilio(m, channel, to, msg);
  if (m.provider === "webhook") return gateway(m, channel, to, msg);
  return { ok: false, error: "No SMS or WhatsApp provider is set", permanent: true };
}
