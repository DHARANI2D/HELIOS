// Windows Event Log (.evtx) reader — pure TypeScript, no dependencies.
//
// Layout: a 4 KiB file header, then 64 KiB chunks. Each chunk holds event
// records whose payload is Binary XML (BinXML). Element names and templates
// are stored once per chunk and referenced by chunk-relative offset; a
// record is usually a template instance plus an array of substitution
// values. We expand that into a small element tree and read the System
// block and EventData / UserData out of it.
//
// Validated record-for-record against python-evtx on Security, System,
// Application and Sysmon logs (including one with corrupted chunks). A
// record that can't be decoded is reported and skipped, never guessed at.

export interface EvtxEvent {
  recordId: number;
  provider?: string;
  eventId?: number;
  level?: number;
  channel?: string;
  computer?: string;
  timeCreated?: Date;
  userSid?: string;
  // EventData <Data Name="…"> values (unnamed ones as Data0, Data1…), or the
  // leaf elements of UserData.
  data: Record<string, string>;
}

export interface EvtxResult {
  events: EvtxEvent[];
  errors: string[];
  truncated: boolean;
}

const FILE_MAGIC = "ElfFile\0";
const CHUNK_MAGIC = "ElfChnk\0";
const CHUNK_SIZE = 0x10000;
const FILE_HEADER_SIZE = 0x1000;
const RECORD_MAGIC = 0x00002a2a;
const MAX_ERRORS = 20;

export function isEvtx(bytes: Uint8Array) {
  return bytes.byteLength >= 8 && ascii(bytes, 0, 8) === FILE_MAGIC;
}

function ascii(bytes: Uint8Array, at: number, len: number) {
  let s = "";
  for (let i = 0; i < len; i++) s += String.fromCharCode(bytes[at + i]);
  return s;
}

// --- element tree ----------------------------------------------------------

interface Elem {
  name: string;
  attrs: Record<string, string>;
  children: Node[];
}
type Node = Elem | string;

// A template body before substitution: values may be placeholders.
type TPart = string | { sub: number; optional: boolean };
interface TElem {
  name: string;
  attrs: Array<{ name: string; value: TPart[] }>;
  children: TNode[];
}
type TNode = TElem | TPart;

// A substitution value: rendered text, a nested fragment, or nothing.
type SubValue = string | Node[] | null;

class EvtxError extends Error {}

const UTF16 = new TextDecoder("utf-16le");
const LATIN1 = new TextDecoder("latin1");
const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

class Chunk {
  private readonly view: DataView;
  private readonly names = new Map<number, string>();
  private readonly templates = new Map<number, TNode[]>();

  constructor(
    private readonly bytes: Uint8Array,
    private readonly base: number,
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  private u8(at: number) {
    if (at >= this.bytes.byteLength) throw new EvtxError("read past end of file");
    return this.bytes[at];
  }
  private u16(at: number) {
    return this.view.getUint16(at, true);
  }
  private u32(at: number) {
    return this.view.getUint32(at, true);
  }
  private rel(abs: number) {
    return abs - this.base;
  }

  private utf16(at: number, chars: number) {
    return UTF16.decode(this.bytes.subarray(at, at + chars * 2));
  }

  // Chunk-relative offset → [name, size of the name record].
  private name(offset: number): [string, number] {
    const at = this.base + offset;
    const len = this.u16(at + 6);
    const size = 8 + len * 2 + 2;
    let cached = this.names.get(offset);
    if (cached === undefined) {
      cached = this.utf16(at + 8, len);
      this.names.set(offset, cached);
    }
    return [cached, size];
  }

  // Reads a name reference at `at` (a u32 chunk offset); when the name record
  // is stored inline right after the reference, skips over it.
  private nameRef(at: number, tokenAt: number): [string, number] {
    const offset = this.u32(at);
    const [name, size] = this.name(offset);
    const next = at + 4;
    return [name, offset > this.rel(tokenAt) ? next + size : next];
  }

  private template(offset: number): [TNode[], number] {
    const at = this.base + offset;
    const dataSize = this.u32(at + 20);
    let body = this.templates.get(offset);
    if (!body) {
      body = this.sequence(at + 24, at + 24 + dataSize).nodes;
      this.templates.set(offset, body);
    }
    return [body, 24 + dataSize];
  }

  // A BinXML fragment: optional fragment header, then elements or template
  // instances, until end-of-stream.
  sequence(at: number, end: number): { nodes: TNode[]; at: number } {
    const nodes: TNode[] = [];
    while (at < end) {
      const token = this.u8(at);
      switch (token & 0x0f) {
        case 0x00:
          return { nodes, at: at + 1 };
        case 0x0f:
          at += 4;
          break;
        case 0x01: {
          const r = this.element(at);
          nodes.push(r.node);
          at = r.at;
          break;
        }
        case 0x0c: {
          const r = this.templateInstance(at);
          nodes.push(...r.nodes);
          at = r.at;
          break;
        }
        default:
          throw new EvtxError(`unexpected token 0x${token.toString(16)} at 0x${at.toString(16)}`);
      }
    }
    return { nodes, at };
  }

  private element(tokenAt: number): { node: TElem; at: number } {
    const token = this.u8(tokenAt);
    let at = tokenAt + 7; // token, dependency id (u16), data size (u32)
    const nameAt = at;
    at += 4;
    if (token & 0x40) at += 4; // attribute list size
    const nameOffset = this.u32(nameAt);
    const [name, nameSize] = this.name(nameOffset);
    if (nameOffset > this.rel(tokenAt)) at += nameSize;

    const node: TElem = { name, attrs: [], children: [] };
    for (;;) {
      const t = this.u8(at) & 0x0f;
      if (t === 0x06) {
        const [attrName, next] = this.nameRef(at + 1, at);
        const value = this.content(next, true);
        node.attrs.push({ name: attrName, value: value.parts });
        at = value.at;
      } else if (t === 0x02) {
        at += 1;
        break;
      } else if (t === 0x03) {
        return { node, at: at + 1 };
      } else {
        throw new EvtxError(`bad start-element token 0x${this.u8(at).toString(16)} at 0x${at.toString(16)}`);
      }
    }

    for (;;) {
      const t = this.u8(at) & 0x0f;
      if (t === 0x04) return { node, at: at + 1 };
      if (t === 0x01) {
        const r = this.element(at);
        node.children.push(r.node);
        at = r.at;
      } else if (t === 0x0c) {
        const r = this.templateInstance(at);
        node.children.push(...r.nodes);
        at = r.at;
      } else {
        const r = this.content(at, false);
        if (r.at === at) throw new EvtxError(`bad element content token 0x${this.u8(at).toString(16)} at 0x${at.toString(16)}`);
        node.children.push(...r.parts);
        at = r.at;
      }
    }
  }

  // Character content: values, substitutions, CDATA, char/entity refs and
  // processing instructions. For an attribute, stops at the first part.
  private content(at: number, single: boolean): { parts: TPart[]; at: number } {
    const parts: TPart[] = [];
    for (;;) {
      const token = this.u8(at);
      switch (token & 0x0f) {
        case 0x05: {
          const type = this.u8(at + 1);
          if (type === 0x01) {
            const chars = this.u16(at + 2);
            parts.push(printable(this.utf16(at + 4, chars)));
            at += 4 + chars * 2;
          } else if (type === 0x02) {
            const len = this.u16(at + 2);
            parts.push(LATIN1.decode(this.bytes.subarray(at + 4, at + 4 + len)));
            at += 4 + len;
          } else {
            throw new EvtxError(`unsupported inline value type 0x${type.toString(16)}`);
          }
          break;
        }
        case 0x0d:
        case 0x0e:
          parts.push({ sub: this.u16(at + 1), optional: (token & 0x0f) === 0x0e });
          at += 4;
          break;
        case 0x07: {
          const chars = this.u16(at + 1);
          parts.push(this.utf16(at + 3, chars));
          at += 3 + chars * 2;
          break;
        }
        case 0x08:
          parts.push(String.fromCharCode(this.u16(at + 1)));
          at += 3;
          break;
        case 0x09: {
          const [entity, next] = this.nameRef(at + 1, at);
          parts.push(ENTITIES[entity] ?? `&${entity};`);
          at = next;
          break;
        }
        case 0x0a: {
          const [, next] = this.nameRef(at + 1, at);
          at = next;
          break;
        }
        case 0x0b:
          at += 3 + this.u16(at + 1) * 2;
          break;
        default:
          return { parts, at };
      }
      if (single) return { parts, at };
    }
  }

  private templateInstance(tokenAt: number): { nodes: TNode[]; at: number } {
    const defOffset = this.u32(tokenAt + 6);
    let at = tokenAt + 10;
    const [body, defSize] = this.template(defOffset);
    if (defOffset > this.rel(tokenAt)) at = this.base + defOffset + defSize;

    const count = this.u32(at);
    at += 4;
    const descriptors: Array<{ size: number; type: number }> = [];
    for (let i = 0; i < count; i++) {
      descriptors.push({ size: this.u16(at), type: this.u8(at + 2) });
      at += 4;
    }
    const values: SubValue[] = descriptors.map((d) => {
      const v = this.value(at, d.size, d.type);
      at += d.size;
      return v;
    });
    return { nodes: instantiate(body, values) as TNode[], at };
  }

  private value(at: number, size: number, type: number): SubValue {
    if (type === 0x00 || size === 0) return type === 0x01 || type === 0x02 ? "" : null;
    if (type === 0x21) return resolve(this.sequence(at, at + size).nodes);
    if (type & 0x80) return this.array(at, size, type & 0x7f);
    return this.scalar(at, size, type);
  }

  private array(at: number, size: number, type: number): string {
    if (type === 0x01) {
      return this.utf16(at, size / 2)
        .split("\0")
        .filter((s, i, all) => s !== "" || i < all.length - 1)
        .join(", ");
    }
    const width = { 0x03: 1, 0x04: 1, 0x05: 2, 0x06: 2, 0x07: 4, 0x08: 4, 0x09: 8, 0x0a: 8, 0x0b: 4, 0x0c: 8, 0x0d: 4, 0x0f: 16, 0x11: 8, 0x12: 16, 0x14: 4, 0x15: 8 }[type];
    if (!width) return Array.from(this.bytes.subarray(at, at + size), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
    const out: string[] = [];
    for (let i = 0; i + width <= size; i += width) out.push(this.scalar(at + i, width, type));
    return out.join(", ");
  }

  private scalar(at: number, size: number, type: number): string {
    const v = this.view;
    switch (type) {
      case 0x01:
        return printable(this.utf16(at, size / 2));
      case 0x02:
        return printable(LATIN1.decode(this.bytes.subarray(at, at + size)));
      case 0x03:
        return String(v.getInt8(at));
      case 0x04:
        return String(v.getUint8(at));
      case 0x05:
        return String(v.getInt16(at, true));
      case 0x06:
        return String(v.getUint16(at, true));
      case 0x07:
        return String(v.getInt32(at, true));
      case 0x08:
        return String(v.getUint32(at, true));
      case 0x09:
        return v.getBigInt64(at, true).toString();
      case 0x0a:
        return v.getBigUint64(at, true).toString();
      case 0x0b:
        return String(v.getFloat32(at, true));
      case 0x0c:
        return String(v.getFloat64(at, true));
      case 0x0d:
        return v.getUint32(at, true) ? "true" : "false";
      case 0x0f:
        return guid(this.bytes, at);
      case 0x10:
        return `0x${(size === 8 ? v.getBigUint64(at, true) : BigInt(v.getUint32(at, true))).toString(16).padStart(size * 2, "0")}`;
      case 0x11:
        return filetime(v.getBigUint64(at, true)).toISOString();
      case 0x12: {
        const p = (i: number) => v.getUint16(at + i * 2, true);
        return new Date(Date.UTC(p(0), p(1) - 1, p(3), p(4), p(5), p(6), p(7))).toISOString();
      }
      case 0x13:
        return sid(this.bytes, at);
      case 0x14:
        return `0x${v.getUint32(at, true).toString(16).padStart(8, "0")}`;
      case 0x15:
        return `0x${v.getBigUint64(at, true).toString(16).padStart(16, "0")}`;
      default:
        // Binary (0x0e), handles (0x20), EvtXml (0x23): hex.
        return Array.from(this.bytes.subarray(at, at + size), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
    }
  }

  // Records in this chunk; a corrupt record ends the chunk.
  *records(errors: string[]): Generator<{ recordId: number; root: Node[] }> {
    const freeSpace = this.u32(this.base + 48);
    const end = this.base + Math.min(freeSpace || CHUNK_SIZE, CHUNK_SIZE);
    let at = this.base + 512;
    while (at + 24 <= end && this.u32(at) === RECORD_MAGIC) {
      const size = this.u32(at + 4);
      if (size < 28 || at + size > end) {
        pushError(errors, `record at 0x${at.toString(16)} has an invalid size`);
        return;
      }
      const recordId = Number(this.view.getBigUint64(at + 8, true));
      try {
        const nodes = this.sequence(at + 24, at + size - 4).nodes;
        yield { recordId, root: resolve(nodes) };
      } catch (err) {
        pushError(errors, `record ${recordId}: ${err instanceof Error ? err.message : String(err)}`);
      }
      at += size;
    }
  }
}

// Drops NULs and other control characters (Postgres rejects NUL in text);
// keeps tabs and line breaks.
function printable(s: string) {
  return s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "");
}

function pushError(errors: string[], message: string) {
  if (errors.length < MAX_ERRORS) errors.push(message);
}

function guid(b: Uint8Array, at: number) {
  const hex = (i: number) => b[at + i].toString(16).padStart(2, "0");
  const d1 = [3, 2, 1, 0].map(hex).join("");
  const d2 = [5, 4].map(hex).join("");
  const d3 = [7, 6].map(hex).join("");
  const d4 = [8, 9].map(hex).join("");
  const d5 = [10, 11, 12, 13, 14, 15].map(hex).join("");
  return `{${d1}-${d2}-${d3}-${d4}-${d5}}`;
}

function sid(b: Uint8Array, at: number) {
  const count = b[at + 1];
  let authority = 0;
  for (let i = 2; i < 8; i++) authority = authority * 256 + b[at + i];
  const view = new DataView(b.buffer, b.byteOffset + at + 8, count * 4);
  const subs = Array.from({ length: count }, (_, i) => view.getUint32(i * 4, true));
  return `S-${b[at]}-${authority}${subs.map((s) => `-${s}`).join("")}`;
}

// 100 ns ticks since 1601-01-01.
function filetime(ticks: bigint) {
  return new Date(Number(ticks / BigInt(10_000)) - 11_644_473_600_000);
}

// --- substitution --------------------------------------------------------

function instantiate(nodes: TNode[], values: SubValue[]): Array<TNode | Node> {
  const out: Array<TNode | Node> = [];
  for (const n of nodes) {
    if (typeof n === "string") out.push(n);
    else if ("sub" in n) {
      const v = values[n.sub];
      if (v == null) continue;
      if (typeof v === "string") out.push(v);
      else out.push(...v);
    } else {
      const children = instantiate(n.children, values);
      // An element whose only content was an absent optional substitution
      // still renders (empty), matching the XML Windows produces.
      out.push({
        name: n.name,
        attrs: n.attrs.map((a) => ({ name: a.name, value: a.value.flatMap((p): TPart[] => (typeof p === "string" ? [p] : typeof values[p.sub] === "string" ? [values[p.sub] as string] : [])) })),
        children: children as TNode[],
      });
    }
  }
  return out;
}

// Template trees after substitution contain only strings and elements.
function resolve(nodes: Array<TNode | Node>): Node[] {
  return nodes.flatMap((n): Node[] => {
    if (typeof n === "string") return [n];
    if ("sub" in n) return [];
    const attrs: Record<string, string> = {};
    if (Array.isArray(n.attrs)) for (const a of n.attrs as Array<{ name: string; value: TPart[] }>) attrs[a.name] = a.value.filter((p): p is string => typeof p === "string").join("");
    else Object.assign(attrs, n.attrs);
    return [{ name: n.name, attrs, children: resolve(n.children as Array<TNode | Node>) }];
  });
}

// --- reading events -----------------------------------------------------

function text(node: Elem | undefined): string {
  if (!node) return "";
  return node.children.map((c) => (typeof c === "string" ? c : text(c))).join("");
}

function child(node: Elem | undefined, name: string): Elem | undefined {
  return node?.children.find((c): c is Elem => typeof c !== "string" && c.name === name);
}

function leaves(node: Elem, out: Record<string, string>, prefix = "") {
  for (const c of node.children) {
    if (typeof c === "string") continue;
    const key = prefix ? `${prefix}.${c.name}` : c.name;
    if (c.children.some((g) => typeof g !== "string")) leaves(c, out, key);
    else out[key] = text(c);
  }
}

function toEvent(recordId: number, root: Node[]): EvtxEvent | null {
  const event = root.find((n): n is Elem => typeof n !== "string" && n.name === "Event");
  if (!event) return null;
  const system = child(event, "System");
  const num = (s: string) => (s.trim() && Number.isFinite(Number(s)) ? Number(s) : undefined);
  const time = child(system, "TimeCreated")?.attrs.SystemTime;
  const data: Record<string, string> = {};
  const eventData = child(event, "EventData");
  if (eventData) {
    let i = 0;
    for (const d of eventData.children) {
      if (typeof d === "string") continue;
      data[d.attrs.Name || `Data${i}`] = text(d);
      i++;
    }
  }
  const userData = child(event, "UserData");
  if (userData) leaves(userData, data);
  return {
    recordId,
    provider: child(system, "Provider")?.attrs.Name || child(system, "Provider")?.attrs.EventSourceName,
    eventId: num(text(child(system, "EventID"))),
    level: num(text(child(system, "Level"))),
    channel: text(child(system, "Channel")) || undefined,
    computer: text(child(system, "Computer")) || undefined,
    timeCreated: time ? new Date(time) : undefined,
    userSid: child(system, "Security")?.attrs.UserID || undefined,
    data,
  };
}

export function parseEvtx(bytes: Uint8Array, opts: { maxEvents?: number } = {}): EvtxResult {
  if (!isEvtx(bytes)) throw new Error("Not an EVTX file");
  const maxEvents = opts.maxEvents ?? Infinity;
  const events: EvtxEvent[] = [];
  const errors: string[] = [];
  for (let base = FILE_HEADER_SIZE; base + 512 <= bytes.byteLength; base += CHUNK_SIZE) {
    if (ascii(bytes, base, 8) !== CHUNK_MAGIC) continue; // unused or wiped chunk
    const chunk = new Chunk(bytes, base);
    try {
      for (const { recordId, root } of chunk.records(errors)) {
        const event = toEvent(recordId, root);
        if (!event) continue;
        events.push(event);
        if (events.length >= maxEvents) return { events, errors, truncated: true };
      }
    } catch (err) {
      pushError(errors, `chunk at 0x${base.toString(16)}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return { events, errors, truncated: false };
}
