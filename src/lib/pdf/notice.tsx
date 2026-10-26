import type { RegulatoryNotice } from "@prisma/client";

import { CERT_IN_CONTACT, certInLabel } from "@/lib/compliance/cert-in";
import { NOTICE_DEADLINE, NOTICE_LABEL, SUBMIT_CHANNELS, parseContent } from "@/lib/compliance/notices";
import type { CompanyProfile } from "@/lib/settings";
import { Bullets, DataTable, KeyValues, Paragraph, PdfDocument, Section, pdfDate } from "@/lib/pdf/kit";

// A regulatory notice as the document that is filed: the CERT-In incident
// report, the DPDP intimation and detailed report to the Board, or the
// plain-language notice to the people affected.

type Notice = RegulatoryNotice & { case: { id: string; title: string }; tenant: { name: string } };

function Filing({ n }: { n: Notice }) {
  return (
    <Section title="Filing">
      <KeyValues
        items={[
          ["Status", n.status.toLowerCase().replaceAll("_", " ")],
          ["Deadline", `${NOTICE_DEADLINE[n.kind]}${n.dueAt ? ` · by ${pdfDate(n.dueAt)}` : ""}`],
          ["Clock started", pdfDate(n.clockStartAt)],
          ["Approved by", n.approvedByName ? `${n.approvedByName}${n.approvedVia && n.approvedVia !== "app" ? ` (${n.approvedVia})` : ""} · ${pdfDate(n.approvedAt)}` : "Not yet approved"],
          ["Filed", n.submittedAt ? `${pdfDate(n.submittedAt)} · ${SUBMIT_CHANNELS[n.submittedVia as keyof typeof SUBMIT_CHANNELS] ?? n.submittedVia}${n.reference ? ` · reference ${n.reference}` : ""}` : "Not yet filed"],
          ["Case", `${n.case.title} (${n.case.id})`],
        ]}
      />
    </Section>
  );
}

function CertIn({ n }: { n: Notice }) {
  const c = parseContent("CERT_IN", n.content);
  return (
    <>
      <Section title="Reporting entity and point of contact">
        <KeyValues
          items={[
            ["Organisation", c.reporter.organisation || n.tenant.name],
            ["Sector", c.sector],
            ["Contact", [c.reporter.name, c.reporter.designation].filter(Boolean).join(", ")],
            ["Email", c.reporter.email],
            ["Phone", c.reporter.phone],
            ["Address", c.reporter.address],
          ]}
        />
      </Section>
      <Section title="Incident">
        <KeyValues
          items={[
            ["Type (Annexure I)", n.categories.map((x) => `(${x}) ${certInLabel(x)}`).join("\n")],
            ["Occurred", c.occurredAt ? pdfDate(c.occurredAt) : "Not established"],
            ["Noticed", pdfDate(c.noticedAt || n.clockStartAt)],
            ["Critical systems affected", c.criticalSystems ? "Yes" : "No"],
            ["Also reported to", c.reportedTo],
          ]}
        />
        <Paragraph>{c.description}</Paragraph>
      </Section>
      {c.symptoms.length > 0 && (
        <Section title="Symptoms observed">
          <Bullets items={c.symptoms} />
        </Section>
      )}
      <Section title="Affected systems">
        <DataTable
          columns={[{ label: "Host", width: "28%" }, { label: "IP address", width: "18%", mono: true }, { label: "Operating system", width: "24%" }, { label: "Type", width: "20%" }, { label: "Critical", width: "10%" }]}
          rows={c.affectedSystems.map((s) => [s.hostname, s.ip, s.os, s.type, s.critical ? "Yes" : ""])}
          empty="Not established yet."
        />
      </Section>
      {c.indicators.length > 0 && (
        <Section title="Indicators of compromise">
          <DataTable columns={[{ label: "Type", width: "18%" }, { label: "Value", width: "82%", mono: true }]} rows={c.indicators.map((i) => [i.type.toLowerCase().replace("_", " "), i.value])} />
        </Section>
      )}
      {c.techniques.length > 0 && (
        <Section title="Techniques (MITRE ATT&CK)">
          <Bullets items={c.techniques} />
        </Section>
      )}
      <Section title="Actions taken">
        {c.actionsTaken.length ? <Bullets items={c.actionsTaken} /> : <Paragraph muted>None yet.</Paragraph>}
      </Section>
      {c.additionalInfo && (
        <Section title="Additional information">
          <Paragraph>{c.additionalInfo}</Paragraph>
        </Section>
      )}
      <Paragraph muted>{`Reported to CERT-In (${CERT_IN_CONTACT.email}, ${CERT_IN_CONTACT.phone}) under its directions of 28 April 2022 under section 70B(6) of the Information Technology Act, 2000.`}</Paragraph>
    </>
  );
}

function Intimation({ n }: { n: Notice }) {
  const c = parseContent("DPDP_INTIMATION", n.content);
  return (
    <Section title="Description of the breach (Rule 7(2)(a))">
      <KeyValues
        items={[
          ["Data Fiduciary", n.tenant.name],
          ["Nature", c.nature],
          ["Extent", c.extent],
          ["People affected", c.principalsAffected != null ? c.principalsAffected.toLocaleString("en-IN") : "Being established"],
          ["Personal data involved", c.dataCategories.join(", ")],
          ["When", c.occurredAt ? pdfDate(c.occurredAt) : "Being established"],
          ["Where", c.location],
          ["Likely impact", c.likelyImpact],
        ]}
      />
    </Section>
  );
}

function Report({ n, principals }: { n: Notice; principals: RegulatoryNotice | null }) {
  const c = parseContent("DPDP_REPORT", n.content);
  const told = principals?.status === "SUBMITTED" ? `${principals.recipientsCount ?? 0} people were told on ${pdfDate(principals.submittedAt)}.` : "The people affected have not been told yet.";
  return (
    <>
      <Section title="Facts, circumstances and reasons (Rule 7(2)(b)(i))"><Paragraph>{c.facts}</Paragraph></Section>
      <Section title="Measures taken or proposed to mitigate the risk (ii)"><Paragraph>{c.mitigation}</Paragraph></Section>
      <Section title="Findings about the person who caused the breach (iii)"><Paragraph>{c.personFindings || "Not established."}</Paragraph></Section>
      <Section title="Remedial measures to prevent it happening again (iv)"><Paragraph>{c.remediation}</Paragraph></Section>
      <Section title="Intimations to the people affected (v)">
        <Paragraph>{c.principalsReport || told}</Paragraph>
      </Section>
    </>
  );
}

function Principals({ n }: { n: Notice }) {
  const c = parseContent("DPDP_PRINCIPALS", n.content);
  return (
    <>
      <Section title="What happened"><Paragraph>{c.description}</Paragraph></Section>
      <Section title="What it could mean for you"><Paragraph>{c.consequences}</Paragraph></Section>
      <Section title="What we have done"><Paragraph>{c.mitigation}</Paragraph></Section>
      <Section title="What you can do"><Paragraph>{c.safetySteps}</Paragraph></Section>
      <Section title="Who to contact">
        <KeyValues items={[["Name", c.contact.name], ["Email", c.contact.email], ["Phone", c.contact.phone]]} />
      </Section>
    </>
  );
}

export function NoticePdf({ notice: n, company, principals }: { notice: Notice; company: CompanyProfile; principals: RegulatoryNotice | null }) {
  const update = n.sequence > 1 ? ` — update ${n.sequence - 1}` : "";
  return (
    <PdfDocument title={`${NOTICE_LABEL[n.kind]}${update}`} subtitle={`${n.tenant.name} · ${n.case.title}`} docLabel={n.kind === "CERT_IN" ? "CERT-In report" : "DPDP notice"} company={company}>
      {n.kind === "CERT_IN" && <CertIn n={n} />}
      {n.kind === "DPDP_INTIMATION" && <Intimation n={n} />}
      {n.kind === "DPDP_REPORT" && <Report n={n} principals={principals} />}
      {n.kind === "DPDP_PRINCIPALS" && <Principals n={n} />}
      {n.kind !== "DPDP_PRINCIPALS" && <Filing n={n} />}
    </PdfDocument>
  );
}
