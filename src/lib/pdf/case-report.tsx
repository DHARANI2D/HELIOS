import { Text, View } from "@react-pdf/renderer";

import { db } from "@/lib/db";
import { CASE_SOURCE_LABEL, CASE_STATUS_LABEL } from "@/lib/cases/labels";
import { DOMAIN_LABEL } from "@/lib/rbac";
import { ACTION_LABEL } from "@/lib/response/executor";
import { storedTriage } from "@/lib/ai/triage";
import type { InvestigationMetadata } from "@/lib/investigations/service";
import type { ForensicsMetadata } from "@/lib/forensics/service";
import type { CompanyProfile } from "@/lib/settings";
import { Bullets, DataTable, INK, KeyValues, Paragraph, PdfDocument, Section, SeverityText, pdfDate, pdfText, plainMarkdown } from "@/lib/pdf/kit";

const MAX_TIMELINE = 300;

// What a case report holds for a given viewer: clients get what the case
// page shows them (no AI working notes, raw telemetry or internal comments).
export async function loadCaseReport(caseId: string, audience: "staff" | "client") {
  const kase = await db.case.findUniqueOrThrow({
    where: { id: caseId },
    include: {
      tenant: { select: { name: true, isTest: true } },
      assignedTo: { select: { name: true, email: true } },
      detections: { orderBy: { createdAt: "asc" } },
      timeline: { orderBy: [{ occurredAt: "asc" }, { createdAt: "asc" }], take: MAX_TIMELINE },
      mitreTechniques: { include: { technique: { include: { tactic: true } } } },
      indicators: { include: { indicator: true } },
      responseActions: { where: { status: { not: "SHADOW" } }, orderBy: { createdAt: "asc" } },
      aiRuns: audience === "staff" ? { where: { agentKey: { in: ["triage", "phishing", "threat_intel", "investigator"] }, status: { not: "failed" } }, orderBy: { createdAt: "desc" }, take: 1 } : false,
      _count: { select: { timeline: true, events: true } },
    },
  });
  return { kase, audience };
}

type CaseReport = Awaited<ReturnType<typeof loadCaseReport>>;

function InvestigationSections({ meta }: { meta: InvestigationMetadata }) {
  return (
    <>
      {meta.findings && meta.findings.length > 0 && (
        <Section title="Forensic findings">
          <DataTable
            columns={[{ label: "Severity", width: "12%" }, { label: "Finding", width: "54%" }, { label: "ATT&CK", width: "22%" }, { label: "Events", width: "12%", align: "right" }]}
            rows={meta.findings.map((f) => [f.severity, `${f.title} — ${f.description}`, f.techniques.join(", "), f.eventCount])}
          />
        </Section>
      )}
      {meta.rca && (
        <Section title="Root cause analysis">
          <Paragraph>{meta.rca.root_cause}</Paragraph>
          {meta.rca.timeline.length > 0 && <Bullets items={meta.rca.timeline} />}
          <Paragraph muted>
            Confidence {Math.round(meta.rca.confidence_score * 100)}%{meta.qa ? ` · QA ${meta.qa.is_valid ? "validated" : "raised issues"} after ${meta.pipeline.qaIterations} round(s)` : ""} · {meta.input.eventCount.toLocaleString()} events from {meta.input.files.map((f) => f.name).join(", ") || "pasted logs"}
          </Paragraph>
        </Section>
      )}
      {meta.report && (
        <Section title="Investigation report">
          <Paragraph>{plainMarkdown(meta.report)}</Paragraph>
        </Section>
      )}
    </>
  );
}

function ForensicsSections({ meta }: { meta: ForensicsMetadata }) {
  const v = meta.verdict;
  return (
    <>
      {meta.email && (
        <Section title="Message">
          <KeyValues items={[["Subject", meta.email.subject], ["From", meta.email.from], ["To", meta.email.to], ["Reply-To", meta.email.replyTo], ["Sent", meta.email.date ? pdfDate(meta.email.date) : null], ["Message-ID", meta.email.messageId]]} />
        </Section>
      )}
      <Section title={`Verdict: ${v.verdict} (score ${v.totalScore})`}>
        <Paragraph>{v.explanation}</Paragraph>
        <DataTable
          columns={[{ label: "Component", width: "26%" }, { label: "Points", width: "10%", align: "right" }, { label: "Why", width: "64%" }]}
          rows={v.breakdown.map((c) => [c.component, c.points, c.reasons.join("; ")])}
        />
      </Section>
      {meta.attachments.length > 0 && (
        <Section title="Attachments">
          <DataTable
            columns={[{ label: "File", width: "24%" }, { label: "Type", width: "13%" }, { label: "Risk", width: "11%" }, { label: "SHA-256", width: "52%", mono: true, compact: true }]}
            rows={meta.attachments.map((a) => [a.filename, a.fileType, `${a.risk} (+${a.score})`, a.sha256])}
          />
        </Section>
      )}
      {meta.sandbox.length > 0 && (
        <Section title="Link detonation">
          <DataTable
            columns={[{ label: "URL", width: "48%", mono: true }, { label: "Landed on", width: "36%", mono: true }, { label: "Points", width: "16%", align: "right" }]}
            rows={meta.sandbox.map((s) => [s.url, s.error ? `error: ${s.error}` : s.finalUrl ?? "", s.score])}
          />
        </Section>
      )}
      {meta.blockRecommendations.length > 0 && (
        <Section title="Recommended blocks">
          <Bullets items={meta.blockRecommendations} />
        </Section>
      )}
    </>
  );
}

export function CaseReportPdf({ report, company }: { report: CaseReport; company: CompanyProfile }) {
  const { kase, audience } = report;
  const staff = audience === "staff";
  const meta = (kase.metadata ?? {}) as Record<string, unknown>;
  const run = staff && Array.isArray(kase.aiRuns) ? kase.aiRuns[0] : undefined;
  const triage = storedTriage(run?.output);
  return (
    <PdfDocument
      title={kase.title}
      subtitle={`${CASE_SOURCE_LABEL[kase.sourceType]} · case ${kase.id} · report generated ${pdfDate(new Date())}`}
      docLabel={`Incident report${kase.tenant?.isTest ? " (test data)" : ""}`}
      company={company}
    >
      <View style={{ flexDirection: "row", gap: 12, marginBottom: 8 }}>
        <Text>Severity: </Text>
        <SeverityText severity={kase.severity} />
        <Text style={{ color: INK.secondary }}>{pdfText(`Status: ${CASE_STATUS_LABEL[kase.status]}`)}</Text>
      </View>
      <KeyValues
        items={[
          ["Client", kase.tenant ? `${kase.tenant.name}${kase.tenant.isTest ? " (test client)" : ""}` : "Internal"],
          ["Security domain", kase.domain ? DOMAIN_LABEL[kase.domain] : null],
          ["Opened", pdfDate(kase.createdAt)],
          ["Acknowledged", kase.acknowledgedAt ? pdfDate(kase.acknowledgedAt) : "Not yet"],
          ["Contained", kase.containedAt ? pdfDate(kase.containedAt) : null],
          ["Resolved", kase.resolvedAt ? pdfDate(kase.resolvedAt) : null],
          ["Verdict", kase.verdict],
          ["Confidence", kase.confidence != null ? `${Math.round(kase.confidence * 100)}%` : null],
          ...(staff ? ([["Assigned to", kase.assignedTo?.name ?? kase.assignedTo?.email ?? "Unassigned"], ["Escalation tier", `Tier ${kase.tier}`]] as Array<[string, unknown]>) : []),
        ]}
      />

      {kase.summary && (
        <Section title="Summary">
          <Paragraph>{kase.summary}</Paragraph>
        </Section>
      )}
      {kase.rootCauseNarrative && kase.sourceType !== "SOC_INVESTIGATION" && (
        <Section title="Root cause">
          <Paragraph>{kase.rootCauseNarrative}</Paragraph>
        </Section>
      )}

      {triage && run && (
        <Section title="AI first response">
          <Paragraph>{`${triage.verdict.replace("_", " ")} · confidence ${Math.round(triage.confidence * 100)}% · ${run.engine}${run.model ? ` (${run.model})` : ""} · ${pdfDate(run.createdAt)}`}</Paragraph>
          <Paragraph>{triage.summary}</Paragraph>
          {triage.key_findings.length > 0 && <Bullets items={triage.key_findings.map((f) => `${f.finding} [${f.evidence.join(", ")}]`)} />}
          {triage.analyst_next_steps.length > 0 && (
            <>
              <Paragraph muted>For the analyst:</Paragraph>
              <Bullets items={triage.analyst_next_steps} />
            </>
          )}
          <Paragraph muted>{"An AI agent's initial analysis; the analyst's primary analysis takes precedence."}</Paragraph>
        </Section>
      )}

      {kase.sourceType === "SOC_INVESTIGATION" && meta.pipeline ? <InvestigationSections meta={meta as unknown as InvestigationMetadata} /> : null}
      {kase.sourceType === "EMAIL_ANALYSIS" && meta.verdict ? <ForensicsSections meta={meta as unknown as ForensicsMetadata} /> : null}

      <Section title={`Detections (${kase.detections.length})`}>
        <DataTable
          columns={[{ label: "Severity", width: "12%" }, { label: "Detection", width: "60%" }, { label: "When", width: "28%" }]}
          rows={kase.detections.map((d) => [d.severity, d.title, pdfDate(d.createdAt)])}
          empty="No detections."
        />
      </Section>

      <Section title="MITRE ATT&CK">
        <DataTable
          columns={[{ label: "Technique", width: "60%" }, { label: "Tactic", width: "40%" }]}
          rows={kase.mitreTechniques.map((m) => [`${m.technique.id} ${m.technique.name}`, m.technique.tactic?.name ?? ""])}
          empty="Not mapped to ATT&CK."
        />
      </Section>

      <Section title="Indicators">
        <DataTable
          columns={[{ label: "Type", width: "14%" }, { label: "Value", width: "52%", mono: true }, { label: "Role", width: "20%" }, { label: "Reputation", width: "14%", align: "right" }]}
          rows={kase.indicators.map((ci) => [ci.indicator.type.toLowerCase().replace("_", " "), ci.indicator.value, ci.role ?? "", ci.indicator.maliciousScore != null ? ci.indicator.maliciousScore.toFixed(2) : "unknown"])}
          empty="No indicators."
        />
      </Section>

      <Section title="Response actions">
        <DataTable
          columns={[{ label: "Action", width: "24%" }, { label: "Target", width: "30%", mono: true }, { label: "Status", width: "18%" }, { label: "By", width: "10%" }, { label: "When", width: "18%" }]}
          rows={kase.responseActions.map((a) => [ACTION_LABEL[a.actionType], a.target ?? "", a.status.toLowerCase().replaceAll("_", " "), a.source === "ai" ? "AI" : "Analyst", pdfDate(a.createdAt)])}
          empty="No containment was requested."
        />
      </Section>

      <Section title="Timeline">
        <DataTable
          columns={[{ label: "When", width: "20%" }, { label: "Who", width: "16%" }, { label: "What", width: "64%" }]}
          rows={kase.timeline.map((t) => [pdfDate(t.occurredAt), t.actor ?? "", `${t.action}${t.detail ? ` — ${t.detail.slice(0, 400)}` : ""}`])}
          empty="No timeline entries."
        />
        {kase._count.timeline > MAX_TIMELINE && <Paragraph muted>First {MAX_TIMELINE} of {kase._count.timeline} entries.</Paragraph>}
        {staff && kase._count.events > 0 && <Paragraph muted>{kase._count.events.toLocaleString()} linked telemetry events are kept in HELIOS.</Paragraph>}
      </Section>
    </PdfDocument>
  );
}
