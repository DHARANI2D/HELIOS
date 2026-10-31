// Targets that need more than one value, written so a person can read them
// and a connector can parse them back: a message purge is
// "<message-id> to a@corp.example, b@corp.example". Pure and client-safe.

const EMAIL = /[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
export const MAX_PURGE_RECIPIENTS = 100;

export const emailsIn = (text: string | null | undefined) => [...new Set((text ?? "").match(EMAIL)?.map((e) => e.toLowerCase()) ?? [])];

export function purgeTarget(messageId: string, recipients: string[]) {
  const id = messageId.trim();
  return `${id.startsWith("<") ? id : `<${id}>`} to ${[...new Set(recipients.map((r) => r.trim().toLowerCase()))].join(", ")}`;
}

export function parsePurgeTarget(target: string): { messageId: string; recipients: string[] } | null {
  const m = /^(<[^<>\s]+>)\s+to\s+([\s\S]+)$/.exec(target.trim());
  if (!m) return null;
  const recipients = emailsIn(m[2]);
  return recipients.length && recipients.length <= MAX_PURGE_RECIPIENTS ? { messageId: m[1], recipients } : null;
}

// The purge an email case points at: its Message-ID and its To and Cc.
export function purgeTargetOfCase(metadata: unknown): string | null {
  const email = (metadata as { email?: { messageId?: string; to?: string; cc?: string } } | null)?.email;
  if (!email?.messageId) return null;
  const recipients = emailsIn(`${email.to ?? ""} ${email.cc ?? ""}`);
  return recipients.length ? purgeTarget(email.messageId, recipients.slice(0, MAX_PURGE_RECIPIENTS)) : null;
}
