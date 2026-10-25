// Personal data masked before evidence reaches a cloud model, and put back
// in what the model answers. Hosts, accounts, email addresses and IP
// addresses become stable tokens (HOST_1, USER_2, EMAIL_3, IP_4); the map
// stays on the server. The model reasons over tokens, its answer is restored
// before anyone sees it, and grounding checks run on the restored answer, so
// evidence citations still line up. Pure.

export type TokenKind = "HOST" | "USER" | "EMAIL" | "IP";

export interface KnownEntities {
  hosts?: string[];
  users?: string[];
  emails?: string[];
  ips?: string[];
}

const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const TOKEN_RE = /\b(HOST|USER|EMAIL|IP)_(\d+)\b/g;

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export class Redactor {
  private toToken = new Map<string, string>();
  private toValue = new Map<string, string>();
  private counts: Record<TokenKind, number> = { HOST: 0, USER: 0, EMAIL: 0, IP: 0 };

  constructor(known: KnownEntities = {}) {
    for (const v of known.emails ?? []) this.token("EMAIL", v);
    for (const v of known.users ?? []) this.token("USER", v);
    for (const v of known.hosts ?? []) this.token("HOST", v);
    for (const v of known.ips ?? []) this.token("IP", v);
  }

  get size() {
    return this.toToken.size;
  }

  token(kind: TokenKind, value: string): string {
    const v = value.trim();
    if (v.length < 2) return value;
    const key = v.toLowerCase();
    const existing = this.toToken.get(key);
    if (existing) return existing;
    const token = `${kind}_${++this.counts[kind]}`;
    this.toToken.set(key, token);
    this.toValue.set(token, v);
    return token;
  }

  redact(text: string): string {
    // Known values first, longest first, so "jdoe@corp.example" isn't split
    // into a user and a domain; then any address the evidence didn't list.
    let out = text;
    const known = [...this.toToken.entries()].sort((a, b) => b[0].length - a[0].length);
    for (const [value, token] of known) {
      out = out.replace(new RegExp(`(?<![\\w.@-])${escape(value)}(?![\\w@-]|\\.\\w)`, "gi"), token);
    }
    out = out.replace(EMAIL_RE, (m) => this.token("EMAIL", m));
    out = out.replace(IPV4_RE, (m) => this.token("IP", m));
    return out;
  }

  restoreText(text: string): string {
    return text.replace(TOKEN_RE, (m) => this.toValue.get(m) ?? m);
  }

  // Every string in a model's structured answer, restored.
  restore<T>(data: T): T {
    if (typeof data === "string") return this.restoreText(data) as T;
    if (Array.isArray(data)) return data.map((x) => this.restore(x)) as T;
    if (data && typeof data === "object") return Object.fromEntries(Object.entries(data).map(([k, v]) => [k, this.restore(v)])) as T;
    return data;
  }
}
