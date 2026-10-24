import { createCipheriv, createHmac, pbkdf2Sync, timingSafeEqual } from "node:crypto";
import { crc32 } from "node:zlib";
import { inflateSync } from "fflate";

// A ZIP reader that also opens password-protected archives: traditional
// PKWARE encryption ("ZipCrypto") and WinZip AES (AE-1 / AE-2, 128-256 bit),
// the two schemes malware droppers and evidence bundles use. fflate does the
// inflating; this file walks the central directory, decrypts, and checks
// every member against its CRC (or AES authentication code), so a wrong
// password is reported rather than producing garbage.

export interface ZipMember {
  name: string;
  size: number;
  compressedSize: number;
  method: number; // compression after decryption (AES stores it in its extra field)
  encrypted: boolean;
  aesStrength?: 1 | 2 | 3;
  aesVersion?: 1 | 2;
  crc: number;
  flags: number;
  modTime: number;
  localOffset: number;
}

export interface ExtractResult {
  files: Record<string, Uint8Array>;
  // Encrypted members no password opened, and why.
  locked: Array<{ name: string; reason: "no-password" | "wrong-password" }>;
  skipped: string[];
  passwordUsed?: string;
}

const EOCD = 0x06054b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;

export function isZip(data: Uint8Array) {
  return data.length >= 4 && data[0] === 0x50 && data[1] === 0x4b && data[2] === 0x03 && data[3] === 0x04;
}

export function readZipDirectory(data: Uint8Array): ZipMember[] {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let eocd = -1;
  for (let i = data.length - 22; i >= Math.max(0, data.length - 65557); i--) {
    if (view.getUint32(i, true) === EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return [];
  const count = view.getUint16(eocd + 10, true);
  let offset = view.getUint32(eocd + 16, true);
  const members: ZipMember[] = [];
  for (let i = 0; i < count && offset + 46 <= data.length; i++) {
    if (view.getUint32(offset, true) !== CENTRAL) break;
    const flags = view.getUint16(offset + 8, true);
    let method = view.getUint16(offset + 10, true);
    const modTime = view.getUint16(offset + 12, true);
    const crc = view.getUint32(offset + 16, true);
    let compressedSize = view.getUint32(offset + 20, true);
    let size = view.getUint32(offset + 24, true);
    const nameLen = view.getUint16(offset + 28, true);
    const extraLen = view.getUint16(offset + 30, true);
    const commentLen = view.getUint16(offset + 32, true);
    let localOffset = view.getUint32(offset + 42, true);
    // Bit 11: UTF-8 names; otherwise CP437, which is ASCII for what matters here.
    const name = Buffer.from(data.subarray(offset + 46, offset + 46 + nameLen)).toString(flags & 0x800 ? "utf8" : "latin1");
    let aesStrength: ZipMember["aesStrength"];
    let aesVersion: ZipMember["aesVersion"];
    for (let p = offset + 46 + nameLen, end = p + extraLen; p + 4 <= end; ) {
      const id = view.getUint16(p, true);
      const len = view.getUint16(p + 2, true);
      const body = p + 4;
      if (id === 0x0001) {
        // Zip64: only the fields that overflowed are present, in this order.
        let q = body;
        if (size === 0xffffffff) {
          size = Number(view.getBigUint64(q, true));
          q += 8;
        }
        if (compressedSize === 0xffffffff) {
          compressedSize = Number(view.getBigUint64(q, true));
          q += 8;
        }
        if (localOffset === 0xffffffff) localOffset = Number(view.getBigUint64(q, true));
      } else if (id === 0x9901 && len >= 7) {
        aesVersion = view.getUint16(body, true) === 2 ? 2 : 1;
        aesStrength = view.getUint8(body + 4) as 1 | 2 | 3;
        method = view.getUint16(body + 5, true);
      }
      p = body + len;
    }
    members.push({ name, size, compressedSize, method, encrypted: (flags & 0x1) === 1, aesStrength, aesVersion, crc, flags, modTime, localOffset });
    offset += 46 + nameLen + extraLen + commentLen;
  }
  return members;
}

function rawData(data: Uint8Array, m: ZipMember): Uint8Array {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (view.getUint32(m.localOffset, true) !== LOCAL) throw new Error("bad local header");
  const start = m.localOffset + 30 + view.getUint16(m.localOffset + 26, true) + view.getUint16(m.localOffset + 28, true);
  if (start + m.compressedSize > data.length) throw new Error("truncated member");
  return data.subarray(start, start + m.compressedSize);
}

// --- traditional PKWARE encryption ------------------------------------------

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function zipCryptoDecrypt(raw: Uint8Array, password: Uint8Array, m: ZipMember): Uint8Array | null {
  let k0 = 0x12345678;
  let k1 = 0x23456789;
  let k2 = 0x34567890;
  const update = (b: number) => {
    k0 = (CRC_TABLE[(k0 ^ b) & 0xff] ^ (k0 >>> 8)) >>> 0;
    k1 = (Math.imul((k1 + (k0 & 0xff)) >>> 0, 134775813) + 1) >>> 0;
    k2 = (CRC_TABLE[(k2 ^ (k1 >>> 24)) & 0xff] ^ (k2 >>> 8)) >>> 0;
  };
  for (const b of password) update(b);
  if (raw.length < 12) return null;
  const out = new Uint8Array(raw.length - 12);
  let check = 0;
  for (let i = 0; i < raw.length; i++) {
    const t = (k2 | 2) & 0xffff;
    const plain = raw[i] ^ ((Math.imul(t, t ^ 1) >>> 8) & 0xff);
    update(plain);
    if (i < 12) check = plain;
    else out[i - 12] = plain;
    // The 12th header byte checks the password before decrypting the rest.
    if (i === 11 && check !== (m.flags & 0x8 ? (m.modTime >>> 8) & 0xff : m.crc >>> 24)) return null;
  }
  return out;
}

// --- WinZip AES ---------------------------------------------------------------

const AES_KEY_BYTES = { 1: 16, 2: 24, 3: 32 } as const;

function aesDecrypt(raw: Uint8Array, password: Uint8Array, strength: 1 | 2 | 3): Uint8Array | null {
  const keyLen = AES_KEY_BYTES[strength];
  const saltLen = keyLen / 2;
  if (raw.length < saltLen + 2 + 10) return null;
  const salt = raw.subarray(0, saltLen);
  const verifier = raw.subarray(saltLen, saltLen + 2);
  const body = raw.subarray(saltLen + 2, raw.length - 10);
  const mac = raw.subarray(raw.length - 10);
  const derived = pbkdf2Sync(password, salt, 1000, keyLen * 2 + 2, "sha1");
  if (!timingSafeEqual(derived.subarray(keyLen * 2), verifier)) return null;
  const expected = createHmac("sha1", derived.subarray(keyLen, keyLen * 2)).update(body).digest().subarray(0, 10);
  if (!timingSafeEqual(expected, mac)) return null;
  // CTR mode with a little-endian block counter starting at 1 (not the
  // big-endian counter Node's aes-ctr uses), so: ECB over the counters.
  const blocks = Math.ceil(body.length / 16);
  const counters = Buffer.alloc(blocks * 16);
  for (let i = 0; i < blocks; i++) counters.writeUInt32LE((i + 1) >>> 0, i * 16);
  const cipher = createCipheriv(`aes-${keyLen * 8}-ecb`, derived.subarray(0, keyLen), null).setAutoPadding(false);
  const stream = Buffer.concat([cipher.update(counters), cipher.final()]);
  const out = new Uint8Array(body.length);
  for (let i = 0; i < body.length; i++) out[i] = body[i] ^ stream[i];
  return out;
}

function decompress(bytes: Uint8Array, m: ZipMember): Uint8Array {
  if (m.method === 0) return bytes;
  if (m.method === 8) return inflateSync(bytes, { out: new Uint8Array(m.size) });
  throw new Error(`compression method ${m.method} not supported`);
}

// AE-2 drops the CRC (the HMAC covers integrity); everything else is checked.
function intact(out: Uint8Array, m: ZipMember) {
  return (m.aesStrength && m.aesVersion === 2) || crc32(out) >>> 0 === m.crc;
}

export interface ExtractOptions {
  passwords?: string[];
  filter?: (m: ZipMember) => boolean;
  maxMemberBytes?: number;
}

export function extractZip(data: Uint8Array, options: ExtractOptions = {}): ExtractResult {
  const passwords = [...new Set((options.passwords ?? []).filter(Boolean))];
  const max = options.maxMemberBytes ?? 200 * 1024 * 1024;
  const result: ExtractResult = { files: {}, locked: [], skipped: [] };
  for (const m of readZipDirectory(data)) {
    if (m.name.endsWith("/") || (options.filter && !options.filter(m))) continue;
    if (m.size > max) {
      result.skipped.push(`${m.name} (over ${Math.round(max / 1024 / 1024)} MB uncompressed)`);
      continue;
    }
    try {
      const raw = rawData(data, m);
      if (!m.encrypted) {
        const out = decompress(raw, m);
        if (crc32(out) >>> 0 !== m.crc) throw new Error("CRC mismatch");
        result.files[m.name] = out;
        continue;
      }
      if (!passwords.length) {
        result.locked.push({ name: m.name, reason: "no-password" });
        continue;
      }
      // Members of one archive usually share a password: try the one that
      // worked last first.
      const order = result.passwordUsed ? [result.passwordUsed, ...passwords.filter((p) => p !== result.passwordUsed)] : passwords;
      let opened: Uint8Array | null = null;
      for (const password of order) {
        const key = Buffer.from(password, "utf8");
        const plain = m.aesStrength ? aesDecrypt(raw, key, m.aesStrength) : zipCryptoDecrypt(raw, key, m);
        if (!plain) continue;
        try {
          const out = decompress(plain, m);
          if (!intact(out, m)) continue; // a 1-in-256 false header match
          opened = out;
          result.passwordUsed = password;
          break;
        } catch {
          continue;
        }
      }
      if (opened) result.files[m.name] = opened;
      else result.locked.push({ name: m.name, reason: "wrong-password" });
    } catch (err) {
      result.skipped.push(`${m.name} (${err instanceof Error ? err.message : "unreadable"})`);
    }
  }
  return result;
}

// Passwords quoted in a message ("the password is 4471", "PW: Inv-2026"),
// the usual way an encrypted attachment is handed to its victim.
export function passwordsInText(text: string): string[] {
  const out = new Set<string>();
  const re = /\b(?:password|passcode|passwort|mot de passe|contrase(?:ñ|n)a|senha|pwd|pw|pass)\b\s*(?:is|:|=|-|–|—)?\s*(?:is\s+)?["'“‘«]?([^\s"'”’»<>,;]{3,40})/gi;
  for (const m of text.matchAll(re)) {
    const candidate = m[1].replace(/[.)\]]+$/, "");
    if (!/^(?:is|the|for|to|below|above|attached|protected|required|reset|expired?|and|of|your)$/i.test(candidate)) out.add(candidate);
    if (out.size >= 10) break;
  }
  return [...out];
}
