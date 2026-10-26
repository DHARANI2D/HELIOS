import type { ReactElement, ReactNode } from "react";
import { Document, Font, Page, StyleSheet, Text, View, renderToBuffer } from "@react-pdf/renderer";

import type { CompanyProfile } from "@/lib/settings";

// Building blocks for HELIOS's PDF documents (service reports, case reports,
// quotes): A4, Helvetica, the company profile in the header and the
// report footer at the foot of every page. Server-only.

// Wrap whole words: identifiers, hashes and command lines must never come
// out hyphenated.
Font.registerHyphenationCallback((word) => [word]);

export const INK = { text: "#0b0b0b", secondary: "#52514e", muted: "#898781", rule: "#e1e0d9", accent: "#2a78d6", band: "#f4f3ef" };

const SEVERITY_INK: Record<string, string> = { CRITICAL: "#b42318", HIGH: "#c4501f", MEDIUM: "#8a5a00", LOW: "#0b7a0b", INFO: "#52514e" };

// The built-in PDF fonts speak WinAnsi (Latin-1 plus a few typographic
// marks). Map what has a plain equivalent; anything else becomes "?" rather
// than a broken glyph.
const WIN_ANSI_EXTRA = new Set("€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ");
const PLAIN: Record<string, string> = { "→": "->", "←": "<-", "↔": "<->", "≥": ">=", "≤": "<=", "≠": "!=", "✓": "v", "✗": "x", "⚠": "!", " ": " ", " ": " ", "​": "" };

// JSX children may arrive as an array of fragments.
export function pdfText(value: unknown): string {
  const s = Array.isArray(value) ? value.filter((v) => v != null && v !== false).join("") : value == null ? "" : String(value);
  let out = "";
  for (const ch of s) {
    if (PLAIN[ch] !== undefined) out += PLAIN[ch];
    else if (ch === "\t") out += "  ";
    else if (ch === "\n" || ch === "\r") out += ch;
    else {
      const code = ch.codePointAt(0)!;
      if (code < 0x20 || (code >= 0x7f && code < 0xa0)) continue;
      out += code <= 0xff || WIN_ANSI_EXTRA.has(ch) ? ch : "?";
    }
  }
  return out;
}

// Light Markdown → plain text for agent-written reports: headings, bold,
// code fences and links lose their markup, list bullets stay.
export function plainMarkdown(md: string): string {
  return md
    .replace(/```[\s\S]*?```/g, (block) => block.replace(/```\w*\n?/g, ""))
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/\*\*(.+?)\*\*/g, "$1")
    .replace(/(^|\s)\*(\S.*?)\*(?=\s|$)/g, "$1$2")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, "$1 ($2)")
    .replace(/^\s*[-*]\s+/gm, "• ")
    .trim();
}

const styles = StyleSheet.create({
  // Line height lives on the text styles, each with its own font size
  // (react-pdf resolves it against an 18pt default otherwise): set on the
  // page, it pushes the absolutely positioned footer off the page.
  page: { paddingTop: 72, paddingBottom: 56, paddingHorizontal: 44, fontFamily: "Helvetica", fontSize: 9.5, color: INK.text },
  header: { position: "absolute", top: 24, left: 44, right: 44, flexDirection: "row", justifyContent: "space-between", alignItems: "flex-end", borderBottomWidth: 1, borderBottomColor: INK.rule, paddingBottom: 8 },
  brand: { fontFamily: "Helvetica-Bold", fontSize: 10 },
  headerMeta: { fontSize: 8, color: INK.muted, textAlign: "right" },
  footer: { position: "absolute", bottom: 24, left: 44, right: 44, flexDirection: "row", justifyContent: "space-between", fontSize: 7.5, color: INK.muted, borderTopWidth: 1, borderTopColor: INK.rule, paddingTop: 6 },
  title: { fontFamily: "Helvetica-Bold", fontSize: 17, lineHeight: 1.25, marginBottom: 4 },
  subtitle: { fontSize: 10, color: INK.secondary, marginBottom: 14, lineHeight: 1.35 },
  section: { marginTop: 14 },
  sectionTitle: { fontFamily: "Helvetica-Bold", fontSize: 11, marginBottom: 6, paddingBottom: 3, borderBottomWidth: 1, borderBottomColor: INK.rule },
  paragraph: { marginBottom: 6, fontSize: 9.5, lineHeight: 1.4 },
  muted: { color: INK.muted },
  kvRow: { flexDirection: "row", flexWrap: "wrap" },
  kvCell: { width: "50%", paddingVertical: 3, paddingRight: 10 },
  kvLabel: { fontSize: 7.5, color: INK.muted, textTransform: "uppercase", letterSpacing: 0.4 },
  kvValue: { fontSize: 9.5, lineHeight: 1.35 },
  statRow: { flexDirection: "row", flexWrap: "wrap", marginHorizontal: -4 },
  stat: { width: "33.33%", padding: 4 },
  statBox: { backgroundColor: INK.band, borderRadius: 4, padding: 8 },
  statValue: { fontFamily: "Helvetica-Bold", fontSize: 15 },
  statLabel: { fontSize: 7.5, color: INK.secondary, marginBottom: 2 },
  statHint: { fontSize: 7, color: INK.muted, marginTop: 2 },
  table: { borderTopWidth: 1, borderTopColor: INK.rule },
  tr: { flexDirection: "row", borderBottomWidth: 1, borderBottomColor: INK.rule, paddingVertical: 3.5 },
  th: { fontFamily: "Helvetica-Bold", fontSize: 7.5, color: INK.secondary, textTransform: "uppercase", letterSpacing: 0.3, paddingRight: 6 },
  td: { fontSize: 8.5, paddingRight: 6, lineHeight: 1.35 },
  barRow: { flexDirection: "row", alignItems: "center", marginBottom: 4 },
  barLabel: { width: "38%", fontSize: 8.5, paddingRight: 6 },
  barTrack: { flexGrow: 1, height: 6, backgroundColor: INK.band, borderRadius: 3 },
  barFill: { height: 6, backgroundColor: INK.accent, borderRadius: 3 },
  barValue: { width: 36, textAlign: "right", fontSize: 8.5 },
  bullet: { flexDirection: "row", marginBottom: 3, fontSize: 9.5, lineHeight: 1.4 },
  bulletDot: { width: 10 },
});

export function PdfDocument({ title, subtitle, docLabel, company, children }: { title: string; subtitle?: string; docLabel: string; company: CompanyProfile; children: ReactNode }) {
  const brand = company.name || "HELIOS";
  const contact = [company.email, company.phone, company.website].filter(Boolean).join(" · ");
  return (
    <Document title={pdfText(title)} author={pdfText(brand)} creator="HELIOS" producer="HELIOS">
      <Page size="A4" style={styles.page} wrap>
        <View style={styles.header} fixed>
          <View>
            <Text style={styles.brand}>{pdfText(brand)}</Text>
            {contact ? <Text style={styles.headerMeta}>{pdfText(contact)}</Text> : null}
          </View>
          <Text style={styles.headerMeta}>{pdfText(docLabel)}</Text>
        </View>
        <View style={styles.footer} fixed>
          <Text>{pdfText(company.reportFooter || company.legalName || brand)}</Text>
          <Text render={({ pageNumber, totalPages }) => `Page ${pageNumber} of ${totalPages}`} />
        </View>
        <Text style={styles.title}>{pdfText(title)}</Text>
        {subtitle ? <Text style={styles.subtitle}>{pdfText(subtitle)}</Text> : null}
        {children}
      </Page>
    </Document>
  );
}

export function Section({ title, children, breakBefore }: { title: string; children: ReactNode; breakBefore?: boolean }) {
  return (
    <View style={styles.section} break={breakBefore}>
      <Text style={styles.sectionTitle} minPresenceAhead={40}>{pdfText(title)}</Text>
      {children}
    </View>
  );
}

export function Paragraph({ children, muted }: { children: unknown; muted?: boolean }) {
  return <Text style={muted ? [styles.paragraph, styles.muted] : styles.paragraph}>{pdfText(children)}</Text>;
}

export function KeyValues({ items }: { items: Array<[string, unknown]> }) {
  return (
    <View style={styles.kvRow}>
      {items
        .filter(([, v]) => v !== undefined && v !== null && v !== "")
        .map(([label, value]) => (
          <View key={label} style={styles.kvCell} wrap={false}>
            <Text style={styles.kvLabel}>{pdfText(label)}</Text>
            <Text style={styles.kvValue}>{pdfText(value)}</Text>
          </View>
        ))}
    </View>
  );
}

export function Stats({ items }: { items: Array<{ label: string; value: string | number; hint?: string }> }) {
  return (
    <View style={styles.statRow}>
      {items.map((s) => (
        <View key={s.label} style={styles.stat} wrap={false}>
          <View style={styles.statBox}>
            <Text style={styles.statLabel}>{pdfText(s.label)}</Text>
            <Text style={styles.statValue}>{pdfText(s.value)}</Text>
            {s.hint ? <Text style={styles.statHint}>{pdfText(s.hint)}</Text> : null}
          </View>
        </View>
      ))}
    </View>
  );
}

export interface Column {
  label: string;
  width: string; // e.g. "30%"
  align?: "left" | "right";
  mono?: boolean;
  // Hashes and other long unbroken values: a smaller monospace size so a
  // SHA-256 (64 characters) fits half the page width on one line.
  compact?: boolean;
}

export function DataTable({ columns, rows, empty = "None." }: { columns: Column[]; rows: Array<Array<unknown>>; empty?: string }) {
  if (!rows.length) return <Text style={styles.muted}>{pdfText(empty)}</Text>;
  return (
    <View style={styles.table}>
      <View style={styles.tr} fixed>
        {columns.map((c) => (
          <Text key={c.label} style={[styles.th, { width: c.width, textAlign: c.align ?? "left" }]}>{pdfText(c.label)}</Text>
        ))}
      </View>
      {rows.map((r, i) => (
        <View key={i} style={styles.tr} wrap={false}>
          {columns.map((c, j) => (
            <Text key={c.label} style={[styles.td, { width: c.width, textAlign: c.align ?? "left" }, c.mono ? { fontFamily: "Courier", fontSize: c.compact ? 6.4 : 7.5 } : {}]}>{pdfText(r[j])}</Text>
          ))}
        </View>
      ))}
    </View>
  );
}

// Single-series magnitude bars (one hue, the value printed beside each).
export function Bars({ items, empty = "None." }: { items: Array<{ label: string; value: number }>; empty?: string }) {
  if (!items.length) return <Text style={styles.muted}>{pdfText(empty)}</Text>;
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <View>
      {items.map((i) => (
        <View key={i.label} style={styles.barRow} wrap={false}>
          <Text style={styles.barLabel}>{pdfText(i.label)}</Text>
          <View style={styles.barTrack}>
            <View style={[styles.barFill, { width: `${Math.max(2, (i.value / max) * 100)}%` }]} />
          </View>
          <Text style={styles.barValue}>{i.value}</Text>
        </View>
      ))}
    </View>
  );
}

export function Bullets({ items }: { items: unknown[] }) {
  return (
    <View>
      {items.map((item, i) => (
        <View key={i} style={styles.bullet} wrap={false}>
          <Text style={styles.bulletDot}>•</Text>
          <Text style={{ flex: 1 }}>{pdfText(item)}</Text>
        </View>
      ))}
    </View>
  );
}

export function SeverityText({ severity }: { severity: string }) {
  return <Text style={{ fontFamily: "Helvetica-Bold", color: SEVERITY_INK[severity] ?? INK.text }}>{pdfText(severity.charAt(0) + severity.slice(1).toLowerCase())}</Text>;
}

export function pdfDate(d: Date | string | null | undefined, withTime = true): string {
  if (!d) return "—";
  const date = typeof d === "string" ? new Date(d) : d;
  return withTime ? `${date.toISOString().slice(0, 16).replace("T", " ")} UTC` : date.toISOString().slice(0, 10);
}

export const renderPdf = (doc: ReactElement): Promise<Buffer> => renderToBuffer(doc as Parameters<typeof renderToBuffer>[0]);

export async function pdfResponse(doc: ReactElement, filename: string): Promise<Response> {
  const buffer = await renderPdf(doc);
  return new Response(new Uint8Array(buffer), {
    headers: {
      "content-type": "application/pdf",
      "content-disposition": `attachment; filename="${filename.replace(/[^\w.-]+/g, "-")}"`,
      "cache-control": "private, no-store",
    },
  });
}
