import { findPii, findSecrets, type Hit, type PiiKind } from "@/lib/aisec/detectors";

// Privacy mode for the AI gateway: personal data in a conversation is
// swapped for stable placeholders (EMAIL_1, PHONE_2, AADHAAR_1) before the
// request leaves for the model provider, and put back in the answer. The
// provider reasons over placeholders and never receives the values; the map
// lives only for the one request, on HELIOS. Credentials are masked
// outright: there's no reason to give a model a key back. Pure.

const PLACEHOLDER = /\b(EMAIL|PHONE|CARD|AADHAAR|PAN|SSN|IBAN|IP|MRN|ABHA|DOB)_(\d+)\b/g;

export class Masker {
  private toToken = new Map<string, string>();
  private toValue = new Map<string, string>();
  private counts = new Map<string, number>();
  masked = 0;

  constructor(private kinds: readonly PiiKind[]) {}

  private token(hit: Hit) {
    const key = `${hit.label}:${hit.value.toLowerCase()}`;
    const existing = this.toToken.get(key);
    if (existing) return existing;
    const n = (this.counts.get(hit.label) ?? 0) + 1;
    this.counts.set(hit.label, n);
    const token = `${hit.label}_${n}`;
    this.toToken.set(key, token);
    this.toValue.set(token, hit.value);
    return token;
  }

  mask(text: string): string {
    const hits = [...findPii(text, this.kinds), ...findSecrets(text)].sort((a, b) => a.start - b.start);
    let out = "";
    let at = 0;
    for (const h of hits) {
      if (h.start < at) continue;
      out += text.slice(at, h.start) + (h.kind === "secret" ? "[CREDENTIAL REMOVED]" : this.token(h));
      at = h.end;
      this.masked++;
    }
    return out + text.slice(at);
  }

  restore(text: string): string {
    return text.replace(PLACEHOLDER, (m) => this.toValue.get(m) ?? m);
  }

  get size() {
    return this.toValue.size;
  }
}
