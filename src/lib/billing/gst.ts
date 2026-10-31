// India's GST, the parts an invoice needs. Pure.
// - GSTIN: 15 characters, the state code (2 digits), the PAN (10), the
//   entity number, "Z", and a check character (base-36, weights 1 and 2
//   alternating, digits of each product summed in base 36).
// - Tax on a service: within one state, CGST and SGST (UTGST in a Union
//   Territory without a legislature) at half the rate each; between states,
//   IGST at the full rate; to a client outside India, an export of services
//   (zero-rated, under a letter of undertaking), no GST.

export const GST_STATES: Record<string, string> = {
  "01": "Jammu and Kashmir", "02": "Himachal Pradesh", "03": "Punjab", "04": "Chandigarh", "05": "Uttarakhand", "06": "Haryana", "07": "Delhi",
  "08": "Rajasthan", "09": "Uttar Pradesh", "10": "Bihar", "11": "Sikkim", "12": "Arunachal Pradesh", "13": "Nagaland", "14": "Manipur", "15": "Mizoram",
  "16": "Tripura", "17": "Meghalaya", "18": "Assam", "19": "West Bengal", "20": "Jharkhand", "21": "Odisha", "22": "Chhattisgarh", "23": "Madhya Pradesh",
  "24": "Gujarat", "26": "Dadra and Nagar Haveli and Daman and Diu", "27": "Maharashtra", "29": "Karnataka", "30": "Goa", "31": "Lakshadweep",
  "32": "Kerala", "33": "Tamil Nadu", "34": "Puducherry", "35": "Andaman and Nicobar Islands", "36": "Telangana", "37": "Andhra Pradesh", "38": "Ladakh",
  "97": "Other Territory",
};
// Union Territories without a legislature charge UTGST instead of SGST.
const UTGST = new Set(["04", "26", "31", "35", "38"]);

const CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const SHAPE = /^\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/;

export function gstinCheckChar(first14: string) {
  let sum = 0;
  for (let i = 0; i < 14; i++) {
    const product = CHARS.indexOf(first14[i]) * (i % 2 === 0 ? 1 : 2);
    sum += Math.floor(product / 36) + (product % 36);
  }
  return CHARS[(36 - (sum % 36)) % 36];
}

export function gstinProblem(value: string): string | null {
  const v = value.trim().toUpperCase();
  if (!SHAPE.test(v)) return "A GSTIN is 15 characters: state code, PAN, entity number, Z and a check character";
  if (!GST_STATES[v.slice(0, 2)]) return `${v.slice(0, 2)} isn't a GST state code`;
  if (gstinCheckChar(v.slice(0, 14)) !== v[14]) return "The GSTIN's check character doesn't match: check for a typo";
  return null;
}

export const stateOfGstin = (gstin: string | null | undefined) => (gstin && !gstinProblem(gstin) ? gstin.trim().slice(0, 2) : null);

export type TaxMode = "intra" | "inter" | "export" | "none";

export interface TaxLine {
  label: string;
  ratePct: number;
  amount: number; // minor units
}

// The tax on a taxable value in minor units (paise), each head rounded.
export function gstFor(input: { supplierState: string | null; recipientState: string | null; recipientInIndia: boolean; ratePct: number }, taxable: number): { mode: TaxMode; lines: TaxLine[] } {
  if (!input.supplierState || input.ratePct <= 0) return { mode: "none", lines: [] };
  if (!input.recipientInIndia) return { mode: "export", lines: [] };
  if (!input.recipientState) throw new Error("The client's state is needed to work out the place of supply");
  if (input.recipientState !== input.supplierState) return { mode: "inter", lines: [{ label: `IGST ${input.ratePct}%`, ratePct: input.ratePct, amount: Math.round((taxable * input.ratePct) / 100) }] };
  const half = input.ratePct / 2;
  const each = Math.round((taxable * half) / 100);
  return { mode: "intra", lines: [{ label: `CGST ${half}%`, ratePct: half, amount: each }, { label: `${UTGST.has(input.recipientState) ? "UTGST" : "SGST"} ${half}%`, ratePct: half, amount: each }] };
}

// India's financial year runs April to March: "26-27" for 2026-04-01 to 2027-03-31 (IST).
export function financialYear(d: Date) {
  const ist = new Date(d.getTime() + 330 * 60_000);
  const y = ist.getUTCFullYear() - (ist.getUTCMonth() < 3 ? 1 : 0);
  return `${String(y % 100).padStart(2, "0")}-${String((y + 1) % 100).padStart(2, "0")}`;
}

// A serial number unique for the financial year, at most 16 characters
// (letters, digits, "-" and "/"), as the CGST rules ask.
export function invoiceNumber(prefix: string, fy: string, seq: number) {
  const n = `${prefix}/${fy}/${String(seq).padStart(4, "0")}`;
  if (n.length > 16 || !/^[A-Za-z0-9/-]+$/.test(n)) throw new Error(`Invoice number "${n}" is too long or has characters GST doesn't allow: shorten the prefix`);
  return n;
}
