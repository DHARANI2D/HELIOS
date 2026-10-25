// A reader for Compound File Binary ([MS-CFB]) — the container behind
// legacy Office documents (.doc, .xls, .ppt), Outlook .msg files and the
// vbaProject.bin inside macro-enabled OOXML. Streams are addressed by path
// ("Macros/VBA/dir"). Every chain is bounded, so a malformed or hostile file
// fails cleanly instead of looping.

export interface CfbEntry {
  path: string;
  type: "storage" | "stream";
  size: number;
}

export interface Cfb {
  entries: CfbEntry[];
  read(path: string): Uint8Array | null;
}

const MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const ENDOFCHAIN = 0xfffffffe;
const FREESECT = 0xffffffff;
const NOSTREAM = 0xffffffff;
const MAX_STREAM = 64 * 1024 * 1024;

export function isCfb(b: Uint8Array) {
  return b.length >= 512 && MAGIC.every((v, i) => b[i] === v);
}

interface DirEntry {
  name: string;
  type: number; // 1 storage, 2 stream, 5 root
  left: number;
  right: number;
  child: number;
  start: number;
  size: number;
}

export function readCfb(data: Uint8Array): Cfb {
  if (!isCfb(data)) throw new Error("not a compound file");
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const sectorSize = 1 << view.getUint16(30, true);
  const miniSectorSize = 1 << view.getUint16(32, true);
  if (sectorSize !== 512 && sectorSize !== 4096) throw new Error("bad sector size");
  const firstDirSector = view.getUint32(48, true);
  const miniCutoff = view.getUint32(56, true);
  const firstMiniFat = view.getUint32(60, true);
  const miniFatCount = view.getUint32(64, true);
  let difatSector = view.getUint32(68, true);
  const difatCount = view.getUint32(72, true);
  const sectorCount = Math.floor((data.length - sectorSize) / sectorSize) + 1;

  const sectorOffset = (s: number) => (s + 1) * sectorSize;

  // FAT sector list: 109 in the header, the rest in the DIFAT chain.
  const fatSectors: number[] = [];
  for (let i = 0; i < 109; i++) {
    const s = view.getUint32(76 + i * 4, true);
    if (s !== FREESECT && s !== ENDOFCHAIN) fatSectors.push(s);
  }
  for (let n = 0; n < difatCount && difatSector !== ENDOFCHAIN && difatSector < sectorCount; n++) {
    const off = sectorOffset(difatSector);
    const per = sectorSize / 4 - 1;
    for (let i = 0; i < per; i++) {
      const s = view.getUint32(off + i * 4, true);
      if (s !== FREESECT && s !== ENDOFCHAIN) fatSectors.push(s);
    }
    difatSector = view.getUint32(off + per * 4, true);
  }
  const fat = new Uint32Array(fatSectors.length * (sectorSize / 4));
  fatSectors.forEach((s, i) => {
    const off = sectorOffset(s);
    if (off + sectorSize > data.length) return;
    for (let j = 0; j < sectorSize / 4; j++) fat[i * (sectorSize / 4) + j] = view.getUint32(off + j * 4, true);
  });

  function chain(start: number, table: Uint32Array, limit: number): number[] {
    const out: number[] = [];
    for (let s = start; s !== ENDOFCHAIN && s < table.length && out.length < limit; s = table[s]) out.push(s);
    return out;
  }

  function readChain(start: number, size: number | null): Uint8Array {
    const sectors = chain(start, fat, sectorCount);
    const out = new Uint8Array(size ?? sectors.length * sectorSize);
    let pos = 0;
    for (const s of sectors) {
      const off = sectorOffset(s);
      const n = Math.min(sectorSize, out.length - pos, data.length - off);
      if (n <= 0) break;
      out.set(data.subarray(off, off + n), pos);
      pos += n;
    }
    return out.subarray(0, Math.min(pos, out.length));
  }

  // Directory entries, 128 bytes each.
  const dirBytes = readChain(firstDirSector, null);
  const dirs: DirEntry[] = [];
  for (let off = 0; off + 128 <= dirBytes.length; off += 128) {
    const dv = new DataView(dirBytes.buffer, dirBytes.byteOffset + off, 128);
    const nameLen = Math.min(dv.getUint16(64, true), 64);
    const name = Buffer.from(dirBytes.subarray(off, off + Math.max(0, nameLen - 2))).toString("utf16le");
    const sizeLow = dv.getUint32(120, true);
    dirs.push({ name, type: dv.getUint8(66), left: dv.getUint32(68, true), right: dv.getUint32(72, true), child: dv.getUint32(76, true), start: dv.getUint32(116, true), size: sectorSize === 512 ? sizeLow : sizeLow + dv.getUint32(124, true) * 2 ** 32 });
  }
  const root = dirs[0];
  if (!root || root.type !== 5) throw new Error("no root entry");

  const miniStream = readChain(root.start, Math.min(root.size, MAX_STREAM));
  const miniFatBytes = miniFatCount ? readChain(firstMiniFat, miniFatCount * sectorSize) : new Uint8Array(0);
  const miniFat = new Uint32Array(miniFatBytes.length / 4);
  for (let i = 0; i < miniFat.length; i++) miniFat[i] = new DataView(miniFatBytes.buffer, miniFatBytes.byteOffset).getUint32(i * 4, true);

  function readMini(start: number, size: number): Uint8Array {
    const out = new Uint8Array(size);
    let pos = 0;
    for (const s of chain(start, miniFat, miniFat.length)) {
      const off = s * miniSectorSize;
      const n = Math.min(miniSectorSize, size - pos, miniStream.length - off);
      if (n <= 0) break;
      out.set(miniStream.subarray(off, off + n), pos);
      pos += n;
    }
    return out.subarray(0, pos);
  }

  // Walk the red-black tree of each storage (in-order) to build paths.
  const entries: CfbEntry[] = [];
  const byPath = new Map<string, DirEntry>();
  const seen = new Set<number>();
  function walk(id: number, prefix: string) {
    if (id === NOSTREAM || id >= dirs.length || seen.has(id)) return;
    seen.add(id);
    const d = dirs[id];
    walk(d.left, prefix);
    const path = prefix ? `${prefix}/${d.name}` : d.name;
    if (d.type === 1 || d.type === 2) {
      entries.push({ path, type: d.type === 1 ? "storage" : "stream", size: d.size });
      byPath.set(path.toLowerCase(), d);
    }
    if (d.type === 1) walk(d.child, path);
    walk(d.right, prefix);
  }
  walk(root.child, "");

  return {
    entries,
    read(path: string) {
      const d = byPath.get(path.toLowerCase());
      if (!d || d.type !== 2 || d.size > MAX_STREAM) return null;
      return d.size < miniCutoff ? readMini(d.start, d.size) : readChain(d.start, d.size);
    },
  };
}
