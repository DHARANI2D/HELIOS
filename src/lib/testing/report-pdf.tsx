import { Text, View } from "@react-pdf/renderer";
import type { SecurityTest } from "@prisma/client";

import type { CompanyProfile } from "@/lib/settings";
import { Bullets, DataTable, KeyValues, Paragraph, PdfDocument, Section, Stats, pdfDate, pdfText, INK } from "@/lib/pdf/kit";
import { CHECKS, type CheckKey } from "@/lib/testing/exposure";
import { SEVERITIES, SEVERITY_RANK, severityCounts, type TestFinding } from "@/lib/testing/findings";
import type { ScopeTarget } from "@/lib/testing/scope";
import { OWASP_LLM } from "@/lib/aisec/frameworks";

// The security test report: who authorised what, what was in scope, what
// was found (worst first) with evidence and how to fix it, and what was
// fixed or accepted since. For the client and their auditors.

type Probe = { at: string; target: string; check: string; result: string };
type Import = { tool: string; file: string; at: string; by: string; kept: number; outOfScope: number };

const SEV_LABEL: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

export function SecurityTestPdf({ test, tenantName, company }: { test: SecurityTest; tenantName: string; company: CompanyProfile }) {
  const targets = (test.targets as unknown as ScopeTarget[]) ?? [];
  const findings = ((test.findings as unknown as TestFinding[] | null) ?? []).slice().sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
  const open = findings.filter((f) => f.status === "open");
  const counts = severityCounts(findings);
  const imports = (test.imports as unknown as Import[] | null) ?? [];
  const probes = (test.probes as unknown as Probe[] | null) ?? [];
  const detailed = open.filter((f) => f.severity !== "info").slice(0, 60);
  // The AI red team's last run, from its probes ("ai/LLM01", result "GOT THROUGH" or not).
  const aiProbes = probes.filter((p) => p.check.startsWith("ai/"));
  const aiRows = OWASP_LLM.flatMap((o) => {
    const ps = aiProbes.filter((p) => p.check === `ai/${o.id}`);
    if (!ps.length) return [];
    const attacks = new Set(ps.map((p) => p.result.replace(/ \([^)]*\):.*$/, ""))).size;
    const through = ps.filter((p) => p.result.endsWith("GOT THROUGH")).length;
    const openN = open.filter((f) => f.owasp?.includes(o.id)).length;
    return [[`${o.id} ${o.name}`, attacks, through, openN] as Array<string | number>];
  });

  return (
    <PdfDocument title={`Security test report: ${test.title}`} subtitle={`${tenantName} · ${pdfDate(test.windowStart)} to ${pdfDate(test.windowEnd)} UTC`} docLabel="Security test report" company={company}>
      <Section title="Summary">
        <Stats items={SEVERITIES.filter((s) => s !== "info").map((s) => ({ label: `${SEV_LABEL[s]} open`, value: counts[s] }))} />
        <Paragraph>
          {`${findings.length} finding(s) in total: ${open.length} open, ${findings.filter((f) => f.status === "fixed").length} fixed, ${findings.filter((f) => f.status === "accepted").length} accepted as a risk. ${test.runs} run(s) of HELIOS's exposure check${imports.length ? ` and ${imports.length} scanner report(s) imported` : ""}. Status: ${test.status}.`}
        </Paragraph>
        <Paragraph muted>{"HELIOS looks at what is exposed to the internet and doesn't exploit anything. Deeper testing runs in established scanners under the same authorisation; their results are included where imported."}</Paragraph>
      </Section>

      <Section title="Authorisation">
        <KeyValues
          items={[
            ["Requested by", `${test.requestedByName} on ${pdfDate(test.createdAt)}`],
            ["Authorised for the client", test.clientAuthorisedAt ? `${test.clientAuthorisedByName} on ${pdfDate(test.clientAuthorisedAt)}` : "Not yet"],
            ["Authorised for HELIOS", test.heliosAuthorisedAt ? `${test.heliosAuthorisedByName} on ${pdfDate(test.heliosAuthorisedAt)}` : "Not yet"],
            ["Window", `${pdfDate(test.windowStart)} to ${pdfDate(test.windowEnd)} UTC`],
            ["Checks", test.checks.map((c) => CHECKS[c as CheckKey] ?? c).join("; ")],
            ...(test.closedReason ? ([["Stopped", `${test.closedByName}: ${test.closedReason}`]] as Array<[string, string]>) : []),
          ]}
        />
        {test.clientAttestation ? <Paragraph muted>{`Client's attestation: "${test.clientAttestation}"`}</Paragraph> : null}
        <Paragraph muted>{`Rules of engagement: ${test.rulesOfEngagement}`}</Paragraph>
      </Section>

      <Section title="Scope">
        <DataTable
          columns={[
            { label: "Target", width: "34%", mono: true },
            { label: "Verified", width: "34%" },
            { label: "Addresses", width: "32%", mono: true },
          ]}
          rows={targets.map((t) => [t.value, t.verified ? t.via ?? "yes" : `No: ${t.problem ?? "not verified"}`, t.addresses.join(", ") || "-"])}
        />
      </Section>

      <Section title="Findings">
        <DataTable
          columns={[
            { label: "Severity", width: "11%" },
            { label: "Finding", width: "39%" },
            { label: "Target", width: "26%", mono: true },
            { label: "Source", width: "14%" },
            { label: "Status", width: "10%" },
          ]}
          rows={findings.filter((f) => f.severity !== "info").map((f) => [SEV_LABEL[f.severity], f.owasp?.length ? `${f.title} (${f.owasp.join(", ")})` : f.title, `${f.target}${f.port ? `:${f.port}` : ""}`, f.source, f.status])}
          empty="Nothing found beyond information."
        />
      </Section>

      {detailed.length > 0 && (
        <Section title="Open findings in detail" breakBefore>
          {detailed.map((f) => (
            <View key={f.id} wrap={false} style={{ marginBottom: 10, paddingBottom: 6, borderBottomWidth: 0.5, borderBottomColor: INK.rule }}>
              <Text style={{ fontSize: 10, fontFamily: "Helvetica-Bold", marginBottom: 2 }}>{pdfText(`${SEV_LABEL[f.severity]} · ${f.title}`)}</Text>
              <Text style={{ fontSize: 8.5, color: INK.secondary, marginBottom: 3 }}>{pdfText(`${f.target}${f.port ? `:${f.port}` : ""} · ${f.source} · first seen ${pdfDate(f.firstSeen)}`)}</Text>
              <Text style={{ fontSize: 9, marginBottom: 2 }}>{pdfText(`Evidence: ${f.evidence}`)}</Text>
              <Text style={{ fontSize: 9, marginBottom: 2 }}>{pdfText(`Fix: ${f.remediation}`)}</Text>
              {f.references.length ? <Text style={{ fontSize: 8, color: INK.muted }}>{pdfText(`References: ${f.references.slice(0, 8).join(", ")}`)}</Text> : null}
            </View>
          ))}
        </Section>
      )}

      {findings.some((f) => f.status !== "open") && (
        <Section title="Fixed and accepted">
          <Bullets items={findings.filter((f) => f.status !== "open").map((f) => `${f.status === "fixed" ? "Fixed" : "Accepted"}: ${f.title} (${f.target}${f.port ? `:${f.port}` : ""})${f.statusNote ? `. ${f.statusNote}` : ""}`)} />
        </Section>
      )}

      {aiRows.length > 0 && (
        <Section title="AI red team (OWASP Top 10 for LLM applications)">
          <DataTable
            columns={[
              { label: "Category", width: "52%" },
              { label: "Attacks", width: "16%", align: "right" },
              { label: "Got through", width: "16%", align: "right" },
              { label: "Open", width: "16%", align: "right" },
            ]}
            rows={aiRows}
          />
          <Paragraph muted>{"Adversarial prompts sent to each AI system's verified chat endpoint in the last run. When the AI refused, HELIOS tried the same goal in other forms (encoded, role-play, split, another language, false authority) before giving up. Payloads were harmless codes and markers."}</Paragraph>
        </Section>
      )}

      {imports.length > 0 && (
        <Section title="Scanner reports included">
          <DataTable
            columns={[
              { label: "Scanner", width: "22%" },
              { label: "File", width: "30%" },
              { label: "Added", width: "28%" },
              { label: "Kept", width: "10%", align: "right" },
              { label: "Out of scope", width: "10%", align: "right" },
            ]}
            rows={imports.map((i) => [i.tool, i.file, `${i.by}, ${pdfDate(i.at)}`, i.kept, i.outOfScope])}
          />
          <Paragraph muted>{"Findings on hosts outside this test's verified scope were left out."}</Paragraph>
        </Section>
      )}

      {probes.length > 0 && (
        <Section title="What HELIOS probed (last run)">
          <DataTable
            columns={[
              { label: "When (UTC)", width: "22%" },
              { label: "Target", width: "24%", mono: true },
              { label: "Check", width: "14%" },
              { label: "Result", width: "40%" },
            ]}
            rows={probes.slice(0, 150).map((p) => [pdfDate(p.at), p.target, p.check, p.result])}
          />
        </Section>
      )}
    </PdfDocument>
  );
}
