// TEST FIXTURE: writes small but structurally real .evtx files — a file
// header, one 64 KiB chunk, and records whose Binary XML is a template
// instance with substitutions, the way Windows writes them. The first record
// defines the template inline (with inline element names); later records
// reference it by offset and reuse names, exercising the reader's caches.

export interface TestRecord {
  provider: string;
  eventId: number;
  time: Date;
  computer: string;
  userSid?: string; // omitted → optional substitution left empty
  data: Record<string, string>; // EventData, all as strings
}

const DATA_FIELDS = ["TargetUserName", "IpAddress", "LogonType", "NewProcessId", "CommandLine"] as const;

class Writer {
  readonly out: number[] = [];
  constructor(private readonly base: number) {}
  get pos() {
    return this.base + this.out.length;
  }
  u8(v: number) {
    this.out.push(v & 0xff);
  }
  u16(v: number) {
    this.u8(v);
    this.u8(v >> 8);
  }
  u32(v: number) {
    this.u16(v & 0xffff);
    this.u16(v >>> 16);
  }
  u64(v: bigint) {
    for (let i = BigInt(0); i < BigInt(8); i++) this.u8(Number((v >> (BigInt(8) * i)) & BigInt(0xff)));
  }
  bytes(b: ArrayLike<number>) {
    for (let i = 0; i < b.length; i++) this.out.push(b[i]);
  }
  utf16(s: string) {
    for (const ch of s) this.u16(ch.charCodeAt(0));
  }
}

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(bytes: ArrayLike<number>) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const utf16 = (s: string) => {
  const w = new Writer(0);
  w.utf16(s);
  return w.out;
};

function filetime(d: Date) {
  return (BigInt(d.getTime()) + BigInt(11_644_473_600_000)) * BigInt(10_000);
}

function sidBytes(sid: string) {
  const [, rev, auth, ...subs] = sid.split("-");
  const w = new Writer(0);
  w.u8(Number(rev));
  w.u8(subs.length);
  const a = BigInt(auth);
  for (let i = BigInt(5); i >= BigInt(0); i--) w.u8(Number((a >> (BigInt(8) * i)) & BigInt(0xff)));
  for (const s of subs) w.u32(Number(s));
  return w.out;
}

// Name records: written inline (right where the reader expects them) on
// first use, referenced by chunk offset afterwards.
class Names {
  private readonly at = new Map<string, number>();
  // Returns the offset to store and, for a first use, the record to write at
  // `inlineAt`.
  resolve(name: string, inlineAt: number): { offset: number; record?: number[] } {
    const known = this.at.get(name);
    if (known !== undefined) return { offset: known };
    this.at.set(name, inlineAt);
    const w = new Writer(0);
    w.u32(0); // next name in hash bucket
    w.u16(0); // hash (not checked by readers)
    w.u16(name.length);
    w.utf16(name);
    w.u16(0);
    return { offset: inlineAt, record: w.out };
  }
}

function open(w: Writer, names: Names, name: string, attrs: Array<[string, (w: Writer) => void]> = []) {
  w.u8(attrs.length ? 0x41 : 0x01);
  w.u16(0xffff); // dependency id
  w.u32(0); // data size (readers walk the tokens instead)
  const { offset, record } = names.resolve(name, w.pos + 4 + (attrs.length ? 4 : 0));
  w.u32(offset);
  if (attrs.length) w.u32(0); // attribute list size
  if (record) w.bytes(record);
  for (const [attr, value] of attrs) {
    w.u8(0x06);
    const r = names.resolve(attr, w.pos + 4);
    w.u32(r.offset);
    if (r.record) w.bytes(r.record);
    value(w);
  }
}

const sub = (index: number, type: number, optional = false) => (w: Writer) => {
  w.u8(optional ? 0x0e : 0x0d);
  w.u16(index);
  w.u8(type);
};
const literal = (text: string) => (w: Writer) => {
  w.u8(0x05);
  w.u8(0x01);
  w.u16(text.length);
  w.utf16(text);
};

function templateBody(w: Writer, names: Names) {
  w.bytes([0x0f, 0x01, 0x01, 0x00]);
  open(w, names, "Event", [["xmlns", literal("http://schemas.microsoft.com/win/2004/08/events/event")]]);
  w.u8(0x02);
  open(w, names, "System");
  w.u8(0x02);
  open(w, names, "Provider", [["Name", sub(0, 0x01)]]);
  w.u8(0x03);
  open(w, names, "EventID");
  w.u8(0x02);
  sub(1, 0x06)(w);
  w.u8(0x04);
  open(w, names, "TimeCreated", [["SystemTime", sub(2, 0x11)]]);
  w.u8(0x03);
  open(w, names, "EventRecordID");
  w.u8(0x02);
  sub(3, 0x0a)(w);
  w.u8(0x04);
  open(w, names, "Computer");
  w.u8(0x02);
  sub(4, 0x01)(w);
  w.u8(0x04);
  open(w, names, "Security", [["UserID", sub(5, 0x13, true)]]);
  w.u8(0x03);
  w.u8(0x04); // </System>
  open(w, names, "EventData");
  w.u8(0x02);
  DATA_FIELDS.forEach((field, i) => {
    open(w, names, "Data", [["Name", literal(field)]]);
    w.u8(0x02);
    sub(6 + i, field === "LogonType" ? 0x08 : field === "NewProcessId" ? 0x15 : 0x01, true)(w);
    w.u8(0x04);
  });
  w.u8(0x04); // </EventData>
  w.u8(0x04); // </Event>
  w.u8(0x00); // end of stream
}

function values(r: TestRecord, recordId: number): Array<{ type: number; bytes: number[] }> {
  const w16 = (s: string) => ({ type: 0x01, bytes: utf16(s) });
  const num = (type: number, size: number, v: bigint) => {
    const w = new Writer(0);
    if (size === 2) w.u16(Number(v));
    else if (size === 4) w.u32(Number(v));
    else w.u64(v);
    return { type, bytes: w.out };
  };
  const d = r.data;
  return [
    w16(r.provider),
    num(0x06, 2, BigInt(r.eventId)),
    num(0x11, 8, filetime(r.time)),
    num(0x0a, 8, BigInt(recordId)),
    w16(r.computer),
    r.userSid ? { type: 0x13, bytes: sidBytes(r.userSid) } : { type: 0x00, bytes: [] },
    d.TargetUserName !== undefined ? w16(d.TargetUserName) : { type: 0x00, bytes: [] },
    d.IpAddress !== undefined ? w16(d.IpAddress) : { type: 0x00, bytes: [] },
    d.LogonType !== undefined ? num(0x08, 4, BigInt(d.LogonType)) : { type: 0x00, bytes: [] },
    d.NewProcessId !== undefined ? num(0x15, 8, BigInt(d.NewProcessId)) : { type: 0x00, bytes: [] },
    d.CommandLine !== undefined ? w16(d.CommandLine) : { type: 0x00, bytes: [] },
  ];
}

export function buildEvtx(records: TestRecord[], opts: { corruptRecord?: number } = {}): Uint8Array {
  const CHUNK = 0x10000;
  const chunk = new Writer(0);
  // Chunk header (512 bytes): magic, record numbers, header size, offsets.
  chunk.bytes([..."ElfChnk\0"].map((c) => c.charCodeAt(0)));
  chunk.u64(BigInt(1));
  chunk.u64(BigInt(records.length));
  chunk.u64(BigInt(1));
  chunk.u64(BigInt(records.length));
  chunk.u32(128);
  const lastRecordField = chunk.out.length;
  chunk.u32(0);
  const freeSpaceField = chunk.out.length;
  chunk.u32(0);
  while (chunk.out.length < 512) chunk.u8(0);

  const names = new Names();
  let templateAt = -1;
  let lastRecordAt = 512;
  records.forEach((r, i) => {
    const recordId = i + 1;
    lastRecordAt = chunk.pos;
    const rec = new Writer(chunk.pos);
    rec.u32(0x00002a2a);
    rec.u32(0); // size, patched below
    rec.u64(BigInt(recordId));
    rec.u64(filetime(r.time));
    rec.bytes([0x0f, 0x01, 0x01, 0x00]);
    if (opts.corruptRecord === recordId) {
      rec.u8(0x04); // an end-element token where an element must start
    } else {
      const tokenAt = rec.pos;
      rec.u8(0x0c);
      rec.u8(0x01);
      rec.u32(1); // template id
      if (templateAt < 0) {
        templateAt = tokenAt + 10;
        rec.u32(templateAt);
        rec.u32(0); // next template
        rec.bytes(new Array(16).fill(0x11)); // template GUID
        const body = new Writer(rec.pos + 4);
        templateBody(body, names);
        rec.u32(body.out.length);
        rec.bytes(body.out);
      } else {
        rec.u32(templateAt);
      }
      const vals = values(r, recordId);
      rec.u32(vals.length);
      for (const v of vals) {
        rec.u16(v.bytes.length);
        rec.u8(v.type);
        rec.u8(0);
      }
      for (const v of vals) rec.bytes(v.bytes);
    }
    const size = rec.out.length + 4;
    rec.u32(size);
    const s = new Writer(0);
    s.u32(size);
    for (let k = 0; k < 4; k++) rec.out[4 + k] = s.out[k];
    chunk.bytes(rec.out);
  });
  const patch = (field: number, v: number) => {
    const s = new Writer(0);
    s.u32(v);
    for (let k = 0; k < 4; k++) chunk.out[field + k] = s.out[k];
  };
  patch(lastRecordField, lastRecordAt);
  patch(freeSpaceField, chunk.out.length);
  patch(52, crc32(chunk.out.slice(512))); // event records checksum
  patch(124, crc32([...chunk.out.slice(0, 120), ...chunk.out.slice(128, 512)])); // header checksum
  while (chunk.out.length < CHUNK) chunk.u8(0);

  // File header: one chunk, version 3.1, clean.
  const header = new Writer(0);
  header.bytes([..."ElfFile\0"].map((c) => c.charCodeAt(0)));
  header.u64(BigInt(0)); // first chunk
  header.u64(BigInt(0)); // last chunk
  header.u64(BigInt(records.length + 1)); // next record id
  header.u32(128);
  header.u16(1);
  header.u16(3);
  header.u16(0x1000);
  header.u16(1); // chunk count
  while (header.out.length < 120) header.u8(0);
  header.u32(0); // flags
  header.u32(crc32(header.out.slice(0, 120)));

  const file = new Uint8Array(0x1000 + CHUNK);
  file.set(header.out, 0);
  file.set(chunk.out, 0x1000);
  return file;
}
