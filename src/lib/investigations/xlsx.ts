import { strFromU8, unzipSync, type Unzipped } from "fflate";

// Reads Excel workbooks (.xlsx — Office Open XML spreadsheets) into rows
// keyed by the header row, so exported SIEM / EDR search results can be
// investigated like CSV. Cell types follow the spec: shared and inline
// strings, numbers, booleans, errors, ISO dates, and numbers formatted as
// dates (converted to ISO 8601, read as UTC — Excel stores no time zone).
// Formulas contribute their cached value; nothing is evaluated.

export interface XlsxSheet {
  name: string;
  rows: Array<Record<string, string>>;
}

const DATE_FORMAT_IDS = new Set([14, 15, 16, 17, 18, 19, 20, 21, 22, 45, 46, 47]);
const MAX_ROWS = 100_000;

export function isXlsx(entries: Unzipped) {
  return "xl/workbook.xml" in entries && "[Content_Types].xml" in entries;
}

function decode(s: string) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (_, e: string) => {
    if (e[0] === "#") return String.fromCodePoint(e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
    return { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" }[e.toLowerCase()] ?? `&${e};`;
  });
}

function attr(tag: string, name: string) {
  return tag.match(new RegExp(`\\s${name}="([^"]*)"`))?.[1];
}

// All <t> text in a shared or inline string, skipping phonetic runs.
function richText(xml: string) {
  return decode(
    xml
      .replace(/<rPh\b[\s\S]*?<\/rPh>/g, "")
      .match(/<t(?:\s[^>]*)?>([\s\S]*?)<\/t>|<t(?:\s[^>]*)?\/>/g)
      ?.map((t) => t.replace(/^<t[^>]*>|<\/t>$|^<t[^>]*\/>$/g, ""))
      .join("") ?? "",
  );
}

function isDateFormat(code: string) {
  const bare = code
    .replace(/"[^"]*"/g, "")
    .replace(/\\./g, "")
    .replace(/\[(?![hms]+\])[^\]]*\]/gi, "");
  return /[dyhs]/i.test(bare) || /m/i.test(bare.replace(/General/gi, ""));
}

function columnIndex(ref: string) {
  let n = 0;
  for (const c of ref.replace(/\d+$/, "")) n = n * 26 + (c.toUpperCase().charCodeAt(0) - 64);
  return n - 1;
}

function serialToIso(serial: number, date1904: boolean) {
  const ms = Math.round((serial - (date1904 ? 24107 : 25569)) * 86_400_000);
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? String(serial) : d.toISOString();
}

function text(entries: Unzipped, path: string) {
  const f = entries[path];
  return f ? strFromU8(f) : "";
}

export function readXlsx(bytes: Uint8Array | Unzipped): XlsxSheet[] {
  const entries = bytes instanceof Uint8Array ? unzipSync(bytes) : bytes;
  if (!isXlsx(entries)) throw new Error("Not an Excel workbook");

  const workbook = text(entries, "xl/workbook.xml");
  const date1904 = /<workbookPr\b[^>]*\sdate1904="(1|true)"/.test(workbook);
  const rels = new Map<string, string>();
  for (const m of text(entries, "xl/_rels/workbook.xml.rels").matchAll(/<Relationship\b[^>]*>/g)) {
    const id = attr(m[0], "Id");
    const target = attr(m[0], "Target");
    if (id && target) rels.set(id, target.startsWith("/") ? target.slice(1) : `xl/${target.replace(/^\.\//, "")}`);
  }

  const shared = (text(entries, "xl/sharedStrings.xml").match(/<si>[\s\S]*?<\/si>|<si\/>/g) ?? []).map(richText);

  const styles = text(entries, "xl/styles.xml");
  const customFormats = new Map<number, string>();
  for (const m of styles.matchAll(/<numFmt\b[^>]*>/g)) customFormats.set(Number(attr(m[0], "numFmtId")), decode(attr(m[0], "formatCode") ?? ""));
  const cellXfs = styles.match(/<cellXfs\b[^>]*>([\s\S]*?)<\/cellXfs>/)?.[1] ?? "";
  const dateStyles = (cellXfs.match(/<xf\b[^>]*>/g) ?? []).map((xf) => {
    const id = Number(attr(xf, "numFmtId") ?? 0);
    return DATE_FORMAT_IDS.has(id) || (customFormats.has(id) && isDateFormat(customFormats.get(id)!));
  });

  const sheets: XlsxSheet[] = [];
  for (const m of workbook.matchAll(/<sheet\b[^>]*>/g)) {
    const name = decode(attr(m[0], "name") ?? `Sheet${sheets.length + 1}`);
    const path = rels.get(attr(m[0], "r:id") ?? "");
    const xml = path ? text(entries, path) : "";
    if (!xml) continue;

    const grid: string[][] = [];
    for (const row of xml.matchAll(/<row\b[^>]*>([\s\S]*?)<\/row>/g)) {
      if (grid.length >= MAX_ROWS + 1) break;
      const cells: string[] = [];
      let next = 0;
      for (const c of row[1].matchAll(/<c\b([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)) {
        const tag = `<c${c[1]}>`;
        const ref = attr(tag, "r");
        const col = ref ? columnIndex(ref) : next;
        next = col + 1;
        const body = c[2] ?? "";
        const type = attr(tag, "t");
        const raw = body.match(/<v>([\s\S]*?)<\/v>/)?.[1];
        let value = "";
        if (type === "s") value = shared[Number(raw)] ?? "";
        else if (type === "inlineStr") value = richText(body);
        else if (type === "b") value = raw === "1" ? "TRUE" : "FALSE";
        else if (raw !== undefined) {
          value = decode(raw);
          const style = Number(attr(tag, "s") ?? 0);
          if ((type === undefined || type === "n") && dateStyles[style] && value.trim() !== "" && Number.isFinite(Number(value))) value = serialToIso(Number(value), date1904);
        }
        cells[col] = value;
      }
      grid.push(Array.from(cells, (v) => v ?? ""));
    }

    const headerAt = grid.findIndex((r) => r.some((v) => v.trim() !== ""));
    if (headerAt < 0) continue;
    const seen = new Map<string, number>();
    const header = grid[headerAt].map((h, i) => {
      const base = h.trim() || `Column ${i + 1}`;
      const n = (seen.get(base) ?? 0) + 1;
      seen.set(base, n);
      return n > 1 ? `${base} (${n})` : base;
    });
    const rows: Array<Record<string, string>> = [];
    for (const r of grid.slice(headerAt + 1)) {
      if (!r.some((v) => v.trim() !== "")) continue;
      const rec: Record<string, string> = {};
      r.forEach((v, i) => {
        if (v !== "") rec[header[i] ?? `Column ${i + 1}`] = v;
      });
      rows.push(rec);
    }
    sheets.push({ name, rows });
  }
  return sheets;
}
