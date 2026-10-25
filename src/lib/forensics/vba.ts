import { readCfb, type Cfb } from "@/lib/forensics/cfb";

// VBA macro source, recovered from a VBA project ([MS-OVBA]): the "dir"
// stream names each module and where its compressed source starts; module
// streams hold the source run-length compressed. Works on legacy Office
// files (.doc/.xls) and on the vbaProject.bin inside .docm/.xlsm/.pptm.
// (Legacy .ppt keeps its project inside a PowerPoint record stream and isn't
// covered.) desas keyword-scanned the compressed bytes, where compression
// splits words; this reads the actual code.

export interface VbaModule {
  name: string;
  stream: string; // e.g. "Macros/VBA/ThisDocument"
  code: string;
}

const MAX_OUTPUT = 8 * 1024 * 1024;

// [MS-OVBA] 2.4.1 compression: a signature byte, then chunks of up to 4096
// decompressed bytes, each literal or LZ77-style copy tokens.
export function decompressVba(c: Uint8Array): Uint8Array {
  if (c.length === 0 || c[0] !== 0x01) throw new Error("not a compressed VBA container");
  const out: number[] = [];
  let pos = 1;
  while (pos + 2 <= c.length && out.length < MAX_OUTPUT) {
    const header = c[pos] | (c[pos + 1] << 8);
    const chunkEnd = Math.min(pos + (header & 0x0fff) + 3, c.length);
    const compressed = (header & 0x8000) !== 0;
    const chunkStart = out.length;
    pos += 2;
    if (!compressed) {
      const end = Math.min(pos + 4096, c.length);
      for (; pos < end; pos++) out.push(c[pos]);
      continue;
    }
    while (pos < chunkEnd) {
      const flags = c[pos++];
      for (let bit = 0; bit < 8 && pos < chunkEnd; bit++) {
        if (((flags >> bit) & 1) === 0) {
          out.push(c[pos++]);
          continue;
        }
        if (pos + 2 > chunkEnd) {
          pos = chunkEnd;
          break;
        }
        const token = c[pos] | (c[pos + 1] << 8);
        pos += 2;
        const difference = out.length - chunkStart;
        let bitCount = 4;
        while (1 << bitCount < difference) bitCount++;
        const lengthMask = 0xffff >> bitCount;
        const length = (token & lengthMask) + 3;
        const offset = ((token & ~lengthMask & 0xffff) >> (16 - bitCount)) + 1;
        const from = out.length - offset;
        if (from < chunkStart) throw new Error("copy token points before its chunk");
        for (let i = 0; i < length; i++) out.push(out[from + i]);
      }
    }
    pos = chunkEnd;
  }
  return Uint8Array.from(out);
}

interface DirModule {
  name?: string;
  stream?: string;
  offset?: number;
}

// The dir stream is a flat list of (id u16, size u32, data) records, with one
// irregular record: PROJECTVERSION's size field is followed by 6 bytes.
function parseDir(dir: Uint8Array): { codepage: number; modules: DirModule[] } {
  const view = new DataView(dir.buffer, dir.byteOffset, dir.byteLength);
  let codepage = 1252;
  const modules: DirModule[] = [];
  let current: DirModule = {};
  let pos = 0;
  const ascii = (b: Uint8Array) => Buffer.from(b).toString("latin1");
  while (pos + 6 <= dir.length) {
    const id = view.getUint16(pos, true);
    const size = view.getUint32(pos + 2, true);
    pos += 6;
    if (id === 0x0009) {
      pos += 6; // PROJECTVERSION: MajorVersion u32 + MinorVersion u16
      continue;
    }
    if (pos + size > dir.length) break;
    const body = dir.subarray(pos, pos + size);
    pos += size;
    switch (id) {
      case 0x0003:
        codepage = view.getUint16(pos - size, true);
        break;
      case 0x0019: // MODULENAME
        current = { name: ascii(body) };
        break;
      case 0x0047: // MODULENAMEUNICODE
        current.name = Buffer.from(body).toString("utf16le") || current.name;
        break;
      case 0x001a: // MODULESTREAMNAME
        current.stream = ascii(body);
        break;
      case 0x0032: // MODULESTREAMNAME, Unicode
        current.stream = Buffer.from(body).toString("utf16le") || current.stream;
        break;
      case 0x0031: // MODULEOFFSET
        current.offset = new DataView(body.buffer, body.byteOffset, body.byteLength).getUint32(0, true);
        break;
      case 0x002b: // module terminator
        if (current.stream) modules.push(current);
        current = {};
        break;
    }
  }
  return { codepage, modules };
}

function decodeSource(bytes: Uint8Array, codepage: number): string {
  try {
    return new TextDecoder(codepage === 65001 ? "utf-8" : `windows-${codepage}`).decode(bytes);
  } catch {
    return Buffer.from(bytes).toString("latin1");
  }
}

export function extractVbaFromCfb(cfb: Cfb): VbaModule[] {
  const out: VbaModule[] = [];
  for (const entry of cfb.entries.filter((e) => e.type === "stream" && /(^|\/)vba\/dir$/i.test(e.path))) {
    const root = entry.path.slice(0, -"/dir".length);
    const dirRaw = cfb.read(entry.path);
    if (!dirRaw) continue;
    let parsed: ReturnType<typeof parseDir>;
    try {
      parsed = parseDir(decompressVba(dirRaw));
    } catch {
      continue;
    }
    for (const m of parsed.modules) {
      const stream = `${root}/${m.stream}`;
      const bytes = cfb.read(stream);
      if (!bytes || m.offset === undefined || m.offset >= bytes.length) continue;
      try {
        // Office stores line breaks as CRLF; normalize like olevba does.
        const code = decodeSource(decompressVba(bytes.subarray(m.offset)), parsed.codepage).replace(/\r\n?/g, "\n");
        out.push({ name: m.name ?? m.stream!, stream, code });
      } catch {
        // a damaged module doesn't hide the others
      }
    }
  }
  return out;
}

export function extractVba(bytes: Uint8Array): VbaModule[] {
  try {
    return extractVbaFromCfb(readCfb(bytes));
  } catch {
    return [];
  }
}
