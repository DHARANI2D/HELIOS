// TEST FIXTURE: writes a legacy Office compound file (Word 97 layout:
// Macros/PROJECT, Macros/VBA/_VBA_PROJECT, Macros/VBA/dir and one stream per
// module) with real [MS-CFB] sectors, FAT, mini FAT and mini stream, and an
// [MS-OVBA] dir stream. Source is stored with literal-only compression
// (valid; the real .docm fixture covers copy tokens). Output checked with
// oletools' olevba, an independent reader.

const SECTOR = 512;
const MINI = 64;
const CUTOFF = 4096;
const ENDOFCHAIN = 0xfffffffe;
const FREESECT = 0xffffffff;
const FATSECT = 0xfffffffd;
const NOSTREAM = 0xffffffff;

function u16(v: number) {
  return [v & 0xff, (v >> 8) & 0xff];
}
function u32(v: number) {
  return [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
}
const ascii = (s: string) => [...s].map((c) => c.charCodeAt(0));
const utf16 = (s: string) => [...s].flatMap((c) => u16(c.charCodeAt(0)));

// One compressed chunk of literals (inputs under ~3.5 KB stay one chunk).
export function compressLiterals(data: number[]): number[] {
  const out: number[] = [0x01];
  for (let start = 0; start < data.length || start === 0; start += 4096) {
    const part = data.slice(start, start + 4096);
    const body: number[] = [];
    for (let i = 0; i < part.length; i += 8) body.push(0x00, ...part.slice(i, i + 8));
    if (body.length + 2 > 4098) throw new Error("fixture source too large for a literal chunk");
    const header = ((body.length + 2 - 3) & 0x0fff) | (0b011 << 12) | 0x8000;
    out.push(...u16(header), ...body);
    if (part.length === 0) break;
  }
  return out;
}

function record(id: number, data: number[]) {
  return [...u16(id), ...u32(data.length), ...data];
}

export function buildDirStream(modules: Array<{ name: string }>): number[] {
  const out = [
    ...record(0x0001, u32(1)), // win32
    ...record(0x0002, u32(0x409)),
    ...record(0x0014, u32(0x409)),
    ...record(0x0003, u16(1252)),
    ...record(0x0004, ascii("Project")),
    ...record(0x0005, []),
    ...record(0x0040, []),
    ...record(0x0006, []),
    ...record(0x003d, []),
    ...record(0x0007, u32(0)),
    ...record(0x0008, u32(0)),
    ...u16(0x0009), ...u32(4), ...u32(0x5b), ...u16(0x0f), // PROJECTVERSION's irregular layout
    ...record(0x000c, []),
    ...record(0x003c, []),
    ...record(0x000f, u16(modules.length)),
    ...record(0x0013, u16(0xffff)),
  ];
  for (const m of modules) {
    out.push(
      ...record(0x0019, ascii(m.name)),
      ...record(0x0047, utf16(m.name)),
      ...record(0x001a, ascii(m.name)),
      ...record(0x0032, utf16(m.name)),
      ...record(0x001c, []),
      ...record(0x0048, []),
      ...record(0x0031, u32(0)),
      ...record(0x001e, u32(0)),
      ...record(0x002c, u16(0xffff)),
      ...record(0x0021, []),
      ...record(0x002b, []),
    );
  }
  out.push(...record(0x0010, []));
  return out;
}

interface Node {
  name: string;
  type: 1 | 2 | 5;
  data?: number[];
  children: Node[];
  id?: number;
  start?: number;
}

// CFB sibling order: shorter names first, then case-insensitive.
const cfbOrder = (a: Node, b: Node) => a.name.length - b.name.length || a.name.toUpperCase().localeCompare(b.name.toUpperCase());

export function buildCompoundFile(streams: Record<string, number[]>): Uint8Array {
  const root: Node = { name: "Root Entry", type: 5, children: [] };
  for (const [path, data] of Object.entries(streams)) {
    const parts = path.split("/");
    let node = root;
    parts.forEach((part, i) => {
      const last = i === parts.length - 1;
      let next = node.children.find((c) => c.name === part);
      if (!next) {
        next = { name: part, type: last ? 2 : 1, data: last ? data : undefined, children: [] };
        node.children.push(next);
      }
      node = next;
    });
  }
  const nodes: Node[] = [];
  const number = (n: Node) => {
    n.id = nodes.length;
    nodes.push(n);
    n.children.sort(cfbOrder).forEach(number);
  };
  number(root);

  // Mini stream: every stream under the cutoff, 64-byte aligned.
  const mini: number[] = [];
  const miniFat: number[] = [];
  const big: Node[] = [];
  for (const n of nodes.filter((x) => x.type === 2)) {
    if (n.data!.length >= CUTOFF) {
      big.push(n);
      continue;
    }
    const sectors = Math.max(1, Math.ceil(n.data!.length / MINI));
    n.start = n.data!.length ? miniFat.length : ENDOFCHAIN;
    if (!n.data!.length) continue;
    for (let i = 0; i < sectors; i++) miniFat.push(i === sectors - 1 ? ENDOFCHAIN : miniFat.length + 1);
    mini.push(...n.data!, ...new Array(sectors * MINI - n.data!.length).fill(0));
  }

  const dirSectors = Math.ceil((nodes.length * 128) / SECTOR);
  const miniFatSectors = Math.ceil((miniFat.length * 4) / SECTOR);
  const miniStreamSectors = Math.ceil(mini.length / SECTOR);
  const bigSectors = big.map((n) => Math.ceil(n.data!.length / SECTOR));
  const payload = dirSectors + miniFatSectors + miniStreamSectors + bigSectors.reduce((a, b) => a + b, 0);
  let fatSectors = 1;
  while (fatSectors * (SECTOR / 4) < payload + fatSectors) fatSectors++;

  const fat: number[] = new Array(fatSectors * (SECTOR / 4)).fill(FREESECT);
  let next = 0;
  const allocate = (count: number) => {
    const start = next;
    for (let i = 0; i < count; i++) fat[next + i] = i === count - 1 ? ENDOFCHAIN : next + i + 1;
    next += count;
    return count ? start : ENDOFCHAIN;
  };
  for (let i = 0; i < fatSectors; i++) fat[next++] = FATSECT;
  const dirStart = allocate(dirSectors);
  const miniFatStart = allocate(miniFatSectors);
  root.start = allocate(miniStreamSectors);
  big.forEach((n, i) => (n.start = allocate(bigSectors[i])));

  const dir: number[] = [];
  for (const n of nodes) {
    const name = utf16(n.name);
    const entry = [...name, ...new Array(64 - name.length).fill(0), ...u16(name.length + 2), n.type, 1];
    const siblings = nodes.find((p) => p.children.includes(n))?.children ?? [];
    const right = siblings[siblings.indexOf(n) + 1];
    entry.push(...u32(NOSTREAM), ...u32(right ? right.id! : NOSTREAM), ...u32(n.children.length ? n.children[0].id! : NOSTREAM));
    entry.push(...new Array(16 + 4 + 8 + 8).fill(0)); // CLSID, state, times
    const size = n.type === 5 ? mini.length : n.type === 2 ? n.data!.length : 0;
    entry.push(...u32(n.type === 1 ? 0 : n.start ?? ENDOFCHAIN), ...u32(size), ...u32(0));
    dir.push(...entry);
  }
  while (dir.length % SECTOR) dir.push(...new Array(128).fill(0).map((_, i) => (i >= 68 && i < 80 ? 0xff : 0)));

  const header = [
    0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1,
    ...new Array(16).fill(0),
    ...u16(0x3e), ...u16(3), ...u16(0xfffe), ...u16(9), ...u16(6),
    ...new Array(6).fill(0),
    ...u32(0), ...u32(fatSectors), ...u32(dirStart), ...u32(0), ...u32(CUTOFF),
    ...u32(miniFatSectors ? miniFatStart : ENDOFCHAIN), ...u32(miniFatSectors), ...u32(ENDOFCHAIN), ...u32(0),
  ];
  for (let i = 0; i < 109; i++) header.push(...u32(i < fatSectors ? i : FREESECT));
  while (header.length < SECTOR) header.push(0);

  const pad = (bytes: number[], n: number) => [...bytes, ...new Array(n * SECTOR - bytes.length).fill(0)];
  const file = [
    ...header,
    ...fat.flatMap(u32),
    ...dir,
    ...pad([...miniFat, ...new Array(Math.max(0, miniFatSectors * (SECTOR / 4) - miniFat.length)).fill(FREESECT)].flatMap(u32), miniFatSectors),
    ...pad(mini, miniStreamSectors),
    ...big.flatMap((n, i) => pad(n.data!, bigSectors[i])),
  ];
  return Uint8Array.from(file);
}

// A Word 97 document's macro storage with the given modules.
export function buildMacroDocument(modules: Array<{ name: string; code: string }>): Uint8Array {
  const streams: Record<string, number[]> = {
    "Macros/PROJECT": ascii(`ID="{00000000-0000-0000-0000-000000000000}"\r\n${modules.map((m) => `Module=${m.name}`).join("\r\n")}\r\nName="Project"\r\n`),
    "Macros/VBA/_VBA_PROJECT": [0xcc, 0x61, 0xff, 0xff, 0x00, 0x00, 0x00],
    "Macros/VBA/dir": compressLiterals(buildDirStream(modules)),
    WordDocument: new Array(4096).fill(0), // a big stream, so the file has both kinds
  };
  for (const m of modules) streams[`Macros/VBA/${m.name}`] = compressLiterals(ascii(m.code.replace(/\n/g, "\r\n")));
  return buildCompoundFile(streams);
}
