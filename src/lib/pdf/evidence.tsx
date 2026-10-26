import type { ControlEvidence } from "@/lib/compliance/iso27001";
import type { CompanyProfile } from "@/lib/settings";
import { DataTable, Paragraph, PdfDocument, Section, pdfDate } from "@/lib/pdf/kit";

// The ISO/IEC 27001 evidence map as a document for an auditor.
export function EvidencePdf({ controls, company, scope, days, now }: { controls: ControlEvidence[]; company: CompanyProfile; scope: string; days: number; now: Date }) {
  const label = { evidenced: "Evidenced", partial: "Partly", gap: "Gap" } as const;
  return (
    <PdfDocument title="ISO/IEC 27001:2022 evidence" subtitle={`${scope} · last ${days} days to ${pdfDate(now, false)}`} docLabel="Evidence map" company={company}>
      <Paragraph muted>{"What the managed service's own records show for the Annex A controls it touches. Evidence for an auditor, not a certification: a gap means the service has nothing to show for that control."}</Paragraph>
      <Section title="Controls">
        <DataTable
          columns={[{ label: "Control", width: "9%" }, { label: "Name", width: "25%" }, { label: "Status", width: "10%" }, { label: "Evidence", width: "56%" }]}
          rows={controls.map((c) => [`A.${c.id}`, c.name, label[c.status], [...c.evidence.map((e) => `${e.label}: ${e.value}`), c.note].filter(Boolean).join("\n")])}
        />
      </Section>
    </PdfDocument>
  );
}
