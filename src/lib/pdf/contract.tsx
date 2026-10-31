import type { CompanyProfile } from "@/lib/settings";
import type { Criterion } from "@/lib/billing/terms";
import { CYCLE_MONTHS, PILOT_METRICS, formatMoneyPlain } from "@/lib/billing/terms";
import { DataTable, KeyValues, Paragraph, PdfDocument, Section, pdfDate } from "@/lib/pdf/kit";

export interface ContractDoc {
  reference: string;
  kind: "PILOT" | "SUBSCRIPTION";
  status: string;
  clientName: string;
  planName: string | null;
  currency: string;
  monthlyFee: number;
  endpointsCommitted: number;
  overagePerEndpoint: number;
  oneTimeFee: number;
  billingCycle: string;
  paymentTermsDays: number;
  startsAt: Date;
  endsAt: Date;
  autoRenew: boolean;
  noticeDays: number;
  liabilityCapMonths: number;
  autonomyCap: string | null;
  rulebookVersion: number | null;
  dpaReference: string | null;
  terms: string | null;
  criteria: Criterion[];
  signedAt: Date | null;
  signedByName: string | null;
  signedByTitle: string | null;
  signedVia: string | null;
}

const AUTONOMY: Record<string, string> = {
  OFF: "No AI involvement",
  SUGGEST: "The AI only suggests; people act",
  CONTAIN_WITH_APPROVAL: "The AI contains only with a named approver's yes",
  AUTO_CONTAIN: "The AI may contain on its own within the signed rulebook",
};

// The order form: who, what, for how long, at what price, and what HELIOS
// may do on the client's estate without asking. The legal terms are the
// MSSP's own text, as it stood when the contract was sent.
export function ContractPdf({ c, company }: { c: ContractDoc; company: CompanyProfile }) {
  const money = (minor: number) => formatMoneyPlain(minor, c.currency);
  const pilot = c.kind === "PILOT";
  return (
    <PdfDocument
      title={`${pilot ? "Pilot agreement" : "Order form"} ${c.reference}`}
      subtitle={`${c.clientName} · ${pdfDate(c.startsAt, false)} to ${pdfDate(c.endsAt, false)}${c.status === "DRAFT" ? " · DRAFT" : ""}`}
      docLabel={`${pilot ? "Pilot" : "Contract"} ${c.reference}`}
      company={company}
    >
      <Section title="Service">
        <KeyValues
          items={[
            ["Client", c.clientName],
            ["Service", c.planName ? `Managed detection and response, ${c.planName}` : "Managed detection and response"],
            ["Endpoints committed", c.endpointsCommitted.toLocaleString()],
            ["Term", `${pdfDate(c.startsAt, false)} to ${pdfDate(c.endsAt, false)}${c.autoRenew ? ", renewing for the same term unless notice is given" : ""}`],
            ["Notice", c.noticeDays ? `${c.noticeDays} days before the end of the term` : "None"],
          ]}
        />
      </Section>
      <Section title="Fees">
        <KeyValues
          items={[
            ["Monthly fee", money(c.monthlyFee)],
            ["Each endpoint above the commitment, per month", c.overagePerEndpoint ? money(c.overagePerEndpoint) : "Included"],
            ["One-time", c.oneTimeFee ? money(c.oneTimeFee) : "None"],
            ["Invoiced", `${c.billingCycle} (every ${CYCLE_MONTHS[c.billingCycle as keyof typeof CYCLE_MONTHS] ?? 1} month${c.billingCycle === "monthly" ? "" : "s"}), in advance`],
            ["Payment", `within ${c.paymentTermsDays} days of the invoice`],
            ["Taxes", "Fees exclude GST, which is added where it applies"],
          ]}
        />
      </Section>
      <Section title="Automated response">
        <KeyValues
          items={[
            ["AI autonomy consented to", c.autonomyCap ? AUTONOMY[c.autonomyCap] ?? c.autonomyCap : "Recorded when the contract is sent"],
            ["Client rulebook in force", c.rulebookVersion ? `Version ${c.rulebookVersion}, signed by the client in HELIOS` : "None signed yet: automated actions follow the autonomy above and HELIOS's default response policy"],
            ["Liability for automated containment", c.liabilityCapMonths ? `Capped at ${c.liabilityCapMonths} months of fees` : "As set out in the terms"],
          ]}
        />
        <Paragraph muted>HELIOS acts on the client&apos;s estate only within the autonomy above and, once signed, the client&apos;s rulebook; every action is recorded in a tamper-evident audit log and can be rolled back from its case.</Paragraph>
      </Section>
      <Section title="Personal data">
        <Paragraph>{c.dpaReference ? `Personal data is processed under the data processing agreement ${c.dpaReference}, in line with the Digital Personal Data Protection Act, 2023.` : "A data processing agreement under the Digital Personal Data Protection Act, 2023 is to be agreed."}</Paragraph>
      </Section>
      {pilot && c.criteria.length > 0 && (
        <Section title="Pilot success criteria">
          <DataTable columns={[{ label: "Measure", width: "75%" }, { label: "Target", width: "25%", align: "right" }]} rows={c.criteria.map((x) => [PILOT_METRICS[x.metric].label, `${PILOT_METRICS[x.metric].better === "lower" ? "at most" : "at least"} ${x.target}`])} />
          <Paragraph muted>Measured from HELIOS&apos;s own records over the pilot term.</Paragraph>
        </Section>
      )}
      {c.terms && (
        <Section title="Terms" breakBefore>
          <Paragraph>{c.terms}</Paragraph>
        </Section>
      )}
      <Section title="Signature">
        <Paragraph>{c.signedAt ? `Signed for ${c.clientName} by ${c.signedByName}${c.signedByTitle ? `, ${c.signedByTitle}` : ""}, on ${pdfDate(c.signedAt, false)} (${c.signedVia === "in_app" ? "in HELIOS" : c.signedVia === "e_sign" ? "by e-signature" : "on paper"}).` : "Not signed yet."}</Paragraph>
      </Section>
    </PdfDocument>
  );
}
