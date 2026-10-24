import type { CaseSeverity, CaseSource, SecurityDomain } from "@prisma/client";

import { DOMAIN_LABEL } from "@/lib/rbac";
import { CASE_SOURCE_LABEL } from "@/lib/cases/labels";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";
import { ACTION_LABEL } from "@/lib/response/executor";
import { formatDuration, type ServiceReport } from "@/lib/reports";
import type { CompanyProfile } from "@/lib/settings";
import { Bars, DataTable, Paragraph, PdfDocument, Section, Stats, pdfDate } from "@/lib/pdf/kit";

const pct = (n: number | null) => (n == null ? "—" : `${Math.round(n * 100)}%`);

export function ServiceReportPdf({ report, company, scope, internal }: { report: ServiceReport; company: CompanyProfile; scope: string; internal: boolean }) {
  const s = report.summary;
  const r = report.range;
  return (
    <PdfDocument
      title={`Service report — ${scope}`}
      subtitle={`${r.label}: ${pdfDate(r.from, false)} to ${pdfDate(new Date(r.to.getTime() - 1), false)} · generated ${pdfDate(report.generatedAt)}`}
      docLabel="Managed detection & response"
      company={company}
    >
      <Stats
        items={[
          { label: "Cases opened", value: s.opened, hint: `${report.previousSummary.opened} in the previous period` },
          { label: "Cases closed", value: s.closed, hint: `${s.falsePositives} false positive(s)` },
          { label: "Open at report time", value: report.openNow },
          { label: "Median time to acknowledge", value: formatDuration(s.medianAcknowledgeMs), hint: `previous: ${formatDuration(report.previousSummary.medianAcknowledgeMs)}` },
          { label: "Median time to resolve", value: formatDuration(s.medianResolveMs), hint: `previous: ${formatDuration(report.previousSummary.medianResolveMs)}` },
          { label: "Acknowledged within SLA", value: pct(s.sla.compliance), hint: s.sla.met + s.sla.breached ? `${s.sla.met} met, ${s.sla.breached} breached` : "no cases with an SLA" },
        ]}
      />

      <Section title="Cases opened and closed">
        <DataTable
          columns={[{ label: "Period starting", width: "50%" }, { label: "Opened", width: "25%", align: "right" }, { label: "Closed", width: "25%", align: "right" }]}
          rows={report.trend.filter((p) => p.opened || p.closed).map((p) => [p.start, p.opened, p.closed])}
          empty="No cases were opened or closed in this period."
        />
        <Paragraph muted>Periods with no cases are left out. Median time to contain: {formatDuration(s.medianContainMs)}.</Paragraph>
      </Section>

      <Section title="By severity">
        <Bars items={SEVERITY_ORDER.filter((x) => s.bySeverity[x]).map((x) => ({ label: SEVERITY_LABEL[x as CaseSeverity], value: s.bySeverity[x as CaseSeverity] ?? 0 }))} empty="No cases opened." />
      </Section>
      <Section title="By source">
        <Bars items={Object.entries(s.bySource).map(([k, v]) => ({ label: CASE_SOURCE_LABEL[k as CaseSource], value: v ?? 0 })).sort((a, b) => b.value - a.value)} empty="No cases opened." />
      </Section>
      <Section title="By security domain">
        <Bars items={Object.entries(s.byDomain).map(([k, v]) => ({ label: k === "UNASSIGNED" ? "Unassigned" : DOMAIN_LABEL[k as SecurityDomain], value: v })).sort((a, b) => b.value - a.value)} empty="No cases opened." />
      </Section>

      {internal && report.tenants.length > 1 && (
        <Section title="By client">
          <Bars items={report.tenants.map((t) => ({ label: `${t.name}${t.isTest ? " (test)" : ""}`, value: t.count }))} />
        </Section>
      )}

      <Section title="Top ATT&CK techniques">
        <DataTable columns={[{ label: "Technique", width: "80%" }, { label: "Cases", width: "20%", align: "right" }]} rows={report.techniques.map((t) => [`${t.id} ${t.name}`, t.count])} empty="No cases mapped to ATT&CK in this period." />
      </Section>

      <Section title="Malicious indicators">
        <DataTable
          columns={[{ label: "Type", width: "16%" }, { label: "Indicator", width: "60%", mono: true }, { label: "Reputation", width: "12%", align: "right" }, { label: "Cases", width: "12%", align: "right" }]}
          rows={report.indicators.map((i) => [i.type.toLowerCase().replace("_", " "), i.value, i.score.toFixed(2), i.cases])}
          empty="No known-malicious indicators in this period's cases."
        />
      </Section>

      <Section title="AI first responder and containment">
        <Stats
          items={[
            { label: "AI agent runs", value: report.ai.runs, hint: `${report.ai.automatic} automatic, ${report.ai.local} on local models` },
            { label: "Analyst agreement", value: report.ai.rated ? pct(report.ai.agreed / report.ai.rated) : "—", hint: `${report.ai.rated} rated by analysts` },
            { label: "Containment steps", value: report.actions.total, hint: `${report.actions.fromAi} proposed by AI` },
          ]}
        />
        <DataTable
          columns={[{ label: "Action", width: "60%" }, { label: "Requested", width: "40%", align: "right" }]}
          rows={Object.entries(report.actions.byType).sort((a, b) => b[1] - a[1]).map(([type, n]) => [ACTION_LABEL[type as keyof typeof ACTION_LABEL] ?? type, n])}
          empty="No containment was requested."
        />
      </Section>

      {internal && (
        <Section title="Analyst workload">
          <DataTable
            columns={[{ label: "Analyst", width: "40%" }, { label: "Open assigned", width: "20%", align: "right" }, { label: "Closed", width: "20%", align: "right" }, { label: "Median resolve", width: "20%", align: "right" }]}
            rows={report.analysts.map((a) => [a.name, a.openAssigned, a.closed, formatDuration(a.medianResolveMs)])}
            empty="No assigned cases in this period."
          />
        </Section>
      )}
    </PdfDocument>
  );
}
