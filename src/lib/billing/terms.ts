// Contracts and invoices, pure: billing periods, invoice lines and money
// in minor units (paise, cents), and pilot success criteria.

export const CYCLE_MONTHS = { monthly: 1, quarterly: 3, annual: 12 } as const;
export type BillingCycle = keyof typeof CYCLE_MONTHS;

const DAY = 86_400_000;

export const toMinor = (major: number) => Math.round(major * 100);
export const fromMinor = (minor: number) => minor / 100;

export function formatMoney(minor: number, currency: string) {
  try {
    return new Intl.NumberFormat("en-IN", { style: "currency", currency, minimumFractionDigits: 2 }).format(minor / 100);
  } catch {
    return `${currency} ${(minor / 100).toFixed(2)}`;
  }
}

// For PDFs, whose built-in fonts have no rupee sign: "INR 15,000.00".
export const formatMoneyPlain = (minor: number, currency: string) => `${currency} ${(minor / 100).toLocaleString("en-IN", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

function addMonths(d: Date, n: number) {
  const out = new Date(d);
  const day = out.getUTCDate();
  out.setUTCDate(1);
  out.setUTCMonth(out.getUTCMonth() + n);
  // 31 January + 1 month is the last day of February, not 3 March.
  const last = new Date(Date.UTC(out.getUTCFullYear(), out.getUTCMonth() + 1, 0)).getUTCDate();
  out.setUTCDate(Math.min(day, last));
  return out;
}

export interface Period {
  from: Date;
  to: Date; // exclusive
  // Share of a full cycle this period covers (a short last period).
  fraction: number;
}

// The billing periods of a term, cycle by cycle, the last cut at the end.
export function periods(startsAt: Date, endsAt: Date, cycle: BillingCycle): Period[] {
  const out: Period[] = [];
  let from = startsAt;
  for (let i = 1; from < endsAt && i <= 600; i++) {
    const full = addMonths(startsAt, i * CYCLE_MONTHS[cycle]);
    const to = full < endsAt ? full : endsAt;
    const fraction = to < full ? (to.getTime() - from.getTime()) / (full.getTime() - from.getTime()) : 1;
    out.push({ from, to, fraction: Math.round(fraction * 10_000) / 10_000 });
    from = to;
  }
  return out;
}

export function termEnd(startsAt: Date, months: number) {
  return addMonths(startsAt, months);
}

export interface InvoiceLine {
  description: string;
  quantity: number;
  unitPrice: number; // minor units
  amount: number; // minor units
}

export interface Billable {
  planName: string | null;
  cycle: BillingCycle;
  monthlyFee: number;
  endpointsCommitted: number;
  overagePerEndpoint: number;
  oneTimeFee: number;
}

const day = (d: Date) => d.toISOString().slice(0, 10);

// The lines for one period: the fee for the committed endpoints, endpoints
// above the commitment, and the one-time fee on the first invoice.
export function invoiceLines(c: Billable, p: Period, endpointsActual: number, first: boolean): InvoiceLine[] {
  const months = CYCLE_MONTHS[c.cycle] * p.fraction;
  const lines: InvoiceLine[] = [];
  const span = `${day(p.from)} to ${day(new Date(p.to.getTime() - DAY))}`;
  if (c.monthlyFee > 0) {
    const qty = Math.round(months * 10_000) / 10_000;
    lines.push({ description: `Managed detection and response${c.planName ? ` (${c.planName})` : ""}, ${c.endpointsCommitted} endpoints, ${span}`, quantity: qty, unitPrice: c.monthlyFee, amount: Math.round(c.monthlyFee * qty) });
  }
  const over = Math.max(0, endpointsActual - c.endpointsCommitted);
  if (over > 0 && c.overagePerEndpoint > 0) {
    const qty = Math.round(over * months * 10_000) / 10_000;
    lines.push({ description: `${over} endpoints above the ${c.endpointsCommitted} committed, ${span} (endpoint-months)`, quantity: qty, unitPrice: c.overagePerEndpoint, amount: Math.round(c.overagePerEndpoint * qty) });
  }
  if (first && c.oneTimeFee > 0) lines.push({ description: "Onboarding (one-time)", quantity: 1, unitPrice: c.oneTimeFee, amount: c.oneTimeFee });
  return lines;
}

// ---------------------------------------------------------------- pilots

export const PILOT_METRICS = {
  mtta_minutes: { label: "Median time to acknowledge (minutes)", better: "lower" },
  mttc_minutes: { label: "Median time to contain (minutes)", better: "lower" },
  sla_ack_pct: { label: "Cases acknowledged within the SLA (%)", better: "higher" },
  ai_agreement_pct: { label: "AI decisions matching the analysts' (%)", better: "higher" },
  false_containments: { label: "Wrong containments by the AI", better: "lower" },
  critical_false_containments: { label: "Wrong containments of a critical asset", better: "lower" },
  sources_live_pct: { label: "Log sources sending in the last day (%)", better: "higher" },
  qa_agreement_pct: { label: "QA reviews finding the AI right (%)", better: "higher" },
  cases_handled: { label: "Cases handled", better: "higher" },
} as const;
export type PilotMetric = keyof typeof PILOT_METRICS;

export interface Criterion {
  metric: PilotMetric;
  target: number;
}

// Met when at or past the target in the metric's better direction; null
// when there's nothing to measure yet.
export function evaluate(criteria: Criterion[], values: Partial<Record<PilotMetric, number | null>>) {
  return criteria.map((c) => {
    const v = values[c.metric];
    const met = v == null ? null : PILOT_METRICS[c.metric].better === "lower" ? v <= c.target : v >= c.target;
    return { ...c, label: PILOT_METRICS[c.metric].label, value: v ?? null, met };
  });
}

export function median(xs: number[]) {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}
