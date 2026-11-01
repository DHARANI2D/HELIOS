// A small XML reader for scanner reports (Nessus, Greenbone/OpenVAS).
// It builds a plain element tree and never resolves anything beyond the
// five built-in entities and numeric references: no DTDs, no external
// entities, no includes, so a hostile report can't read files or reach
// the network (XXE), and entity expansion can't blow up memory.

export interface XmlNode {
  name: string;
  attrs: Record<string, string>;
  children: XmlNode[];
  text: string;
}

const ENTITIES: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === "#") {
      const code = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : "";
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

export class XmlError extends Error {}

export function parseXml(input: string, opts: { maxNodes?: number } = {}): XmlNode {
  const maxNodes = opts.maxNodes ?? 500_000;
  const root: XmlNode = { name: "#root", attrs: {}, children: [], text: "" };
  const stack: XmlNode[] = [root];
  let i = 0;
  let nodes = 0;
  const n = input.length;
  while (i < n) {
    const lt = input.indexOf("<", i);
    const top = stack[stack.length - 1];
    if (lt === -1) {
      top.text += decodeEntities(input.slice(i));
      break;
    }
    if (lt > i) top.text += decodeEntities(input.slice(i, lt));
    if (input.startsWith("<!--", lt)) {
      const end = input.indexOf("-->", lt + 4);
      if (end === -1) throw new XmlError("Unclosed comment");
      i = end + 3;
    } else if (input.startsWith("<![CDATA[", lt)) {
      const end = input.indexOf("]]>", lt + 9);
      if (end === -1) throw new XmlError("Unclosed CDATA section");
      top.text += input.slice(lt + 9, end);
      i = end + 3;
    } else if (input.startsWith("<?", lt)) {
      const end = input.indexOf("?>", lt + 2);
      if (end === -1) throw new XmlError("Unclosed processing instruction");
      i = end + 2;
    } else if (input.startsWith("<!", lt)) {
      // DOCTYPE and anything like it is skipped, never interpreted.
      let depth = 0;
      let j = lt + 2;
      for (; j < n; j++) {
        if (input[j] === "[") depth++;
        else if (input[j] === "]") depth--;
        else if (input[j] === ">" && depth <= 0) break;
      }
      i = j + 1;
    } else if (input[lt + 1] === "/") {
      const end = input.indexOf(">", lt);
      if (end === -1) throw new XmlError("Unclosed end tag");
      const name = input.slice(lt + 2, end).trim();
      // Tolerate stray end tags: close up to the matching element if open.
      const at = stack.map((x) => x.name).lastIndexOf(name);
      if (at > 0) stack.length = at;
      i = end + 1;
    } else {
      const end = findTagEnd(input, lt);
      if (end === -1) throw new XmlError("Unclosed tag");
      const raw = input.slice(lt + 1, end);
      const selfClosing = raw.endsWith("/");
      const body = selfClosing ? raw.slice(0, -1) : raw;
      const m = /^([^\s/>]+)/.exec(body);
      if (!m) throw new XmlError("Tag without a name");
      const node: XmlNode = { name: m[1], attrs: {}, children: [], text: "" };
      const attrRe = /([^\s=]+)\s*=\s*("([^"]*)"|'([^']*)')/g;
      let a: RegExpExecArray | null;
      while ((a = attrRe.exec(body.slice(m[1].length)))) node.attrs[a[1]] = decodeEntities(a[3] ?? a[4] ?? "");
      if (++nodes > maxNodes) throw new XmlError("The report is too large");
      top.children.push(node);
      if (!selfClosing) stack.push(node);
      i = end + 1;
    }
  }
  return root;
}

function findTagEnd(s: string, from: number): number {
  let quote: string | null = null;
  for (let j = from + 1; j < s.length; j++) {
    const c = s[j];
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === ">") return j;
  }
  return -1;
}

// Helpers for walking the tree.
export const child = (n: XmlNode | undefined, name: string) => n?.children.find((c) => c.name === name);
export const childrenNamed = (n: XmlNode | undefined, name: string) => n?.children.filter((c) => c.name === name) ?? [];
export const textOf = (n: XmlNode | undefined, name: string) => child(n, name)?.text.trim() ?? "";

export function findAll(n: XmlNode, name: string, out: XmlNode[] = []): XmlNode[] {
  for (const c of n.children) {
    if (c.name === name) out.push(c);
    findAll(c, name, out);
  }
  return out;
}
