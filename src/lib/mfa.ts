import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

// Two-step sign-in with an authenticator app: TOTP (RFC 6238, HMAC-SHA1,
// 30-second steps, 6 digits, one step of clock drift either way), plus ten
// single-use recovery codes stored only as hashes. A step that was accepted
// can't be used again, so a code seen over someone's shoulder is dead.
// Pure, apart from randomness.

const STEP_SECONDS = 30;
const DIGITS = 6;
const DRIFT = 1;
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Buffer {
  const clean = text.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error("Not a base32 secret");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export const newSecret = () => base32Encode(randomBytes(20));

// HOTP (RFC 4226) for a counter; TOTP uses the 30-second step as the counter.
export function hotp(secret: Buffer, counter: number, digits = DIGITS): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", secret).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const code = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(code % 10 ** digits).padStart(digits, "0");
}

export const stepAt = (time: Date) => Math.floor(time.getTime() / 1000 / STEP_SECONDS);

export function totp(secretBase32: string, time = new Date(), digits = DIGITS) {
  return hotp(base32Decode(secretBase32), stepAt(time), digits);
}

// The step a code belongs to, if it is valid now and newer than the last one used.
export function verifyTotp(secretBase32: string, code: string, opts: { now?: Date; lastStep?: number | null } = {}): number | null {
  const digits = code.replace(/\s/g, "");
  if (!/^\d{6}$/.test(digits)) return null;
  const key = base32Decode(secretBase32);
  const current = stepAt(opts.now ?? new Date());
  for (let d = -DRIFT; d <= DRIFT; d++) {
    const step = current + d;
    if (opts.lastStep != null && step <= opts.lastStep) continue;
    const expected = Buffer.from(hotp(key, step));
    if (timingSafeEqual(expected, Buffer.from(digits))) return step;
  }
  return null;
}

// otpauth://totp/HELIOS:alice@acme.example?secret=…&issuer=HELIOS
export function otpauthUri(secretBase32: string, account: string, issuer = "HELIOS") {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({ secret: secretBase32, issuer, algorithm: "SHA1", digits: String(DIGITS), period: String(STEP_SECONDS) });
  return `otpauth://totp/${label}?${params}`;
}

// ---------------------------------------------------------------- recovery codes

const hashCode = (code: string) => createHash("sha256").update(code.toLowerCase().replace(/[^a-z0-9]/g, "")).digest("hex");

export function newRecoveryCodes(count = 10) {
  const codes = Array.from({ length: count }, () => {
    const raw = base32Encode(randomBytes(6)).slice(0, 10).toLowerCase();
    return `${raw.slice(0, 5)}-${raw.slice(5)}`;
  });
  return { codes, hashes: codes.map(hashCode) };
}

// The remaining hashes once the code is used, or null if it isn't one of them.
export function consumeRecoveryCode(hashes: string[], code: string): string[] | null {
  const h = hashCode(code);
  if (!hashes.includes(h)) return null;
  return hashes.filter((x) => x !== h);
}
