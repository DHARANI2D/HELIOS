import { View } from "@react-pdf/renderer";

import { CONTROLS } from "@/lib/endpoints/controls";
import { formatMinutes } from "@/lib/plans";
import { formatMoney, type QuoteConfig, type QuoteResult } from "@/lib/pricing/calculator";
import { describeMix } from "@/lib/pricing/endpoint-mix";
import type { CompanyProfile } from "@/lib/settings";
import { Bullets, DataTable, KeyValues, Paragraph, PdfDocument, Section, Stats, pdfDate } from "@/lib/pdf/kit";

interface QuoteDoc {
  reference: string;
  clientName: string;
  currency: string;
  validUntil: Date | null;
  createdAt: Date;
  preparedBy: string | null;
}

// The client-facing proposal. Internal cost and margin never appear.
export function QuotePdf({ quote, cfg, r, company }: { quote: QuoteDoc; cfg: QuoteConfig; r: QuoteResult; company: CompanyProfile }) {
  const money = (usd: number, decimals?: number) => formatMoney(usd, quote.currency, r.fxRate, { decimals });
  const plan = r.plan;
  const discounts: Array<[string, number]> = [
    [`Volume discount (${r.volumeDiscountPct}%)`, r.volumeDiscount],
    [`Term discount (${r.termDiscountPct}%)`, r.termDiscount],
    ["Additional discount", r.extraDiscount],
  ];
  const assumptions = [
    `Third-party licences at ${r.lines.some((l) => l.basis === "list") ? "vendor list prices" : "agreed prices"}; final pricing subject to vendor confirmation.`,
    `Amounts in ${quote.currency} at 1 USD = ${r.fxRate} ${quote.currency}.`,
    cfg.ai.mode === "cloud" && r.aiUsage ? `AI usage estimated at about ${r.aiUsage.alertsPerMonth.toLocaleString()} alerts (${r.aiUsage.runsPerMonth.toLocaleString()} AI runs) per month on ${cfg.ai.model}${r.aiUsage.source === "history" ? ", based on measured volumes" : ""}.` : null,
    cfg.ai.mode === "local" ? "Local AI hardware is installed on the client's premises or a dedicated host; telemetry stays on-premises." : null,
    cfg.commercial.term === "monthly" ? "Month-to-month, 30 days' notice." : cfg.commercial.term === "annual" ? "12-month term, billed annually in advance." : "36-month term.",
  ].filter(Boolean);

  return (
    <PdfDocument
      title={`Managed security proposal for ${quote.clientName}`}
      subtitle={`${quote.reference} · issued ${pdfDate(quote.createdAt, false)} · valid until ${quote.validUntil ? pdfDate(quote.validUntil, false) : "—"}`}
      docLabel={`Quote ${quote.reference}`}
      company={company}
    >
      <Paragraph>
        {plan ? `${plan.name}${plan.tagline ? ` — ${plan.tagline}` : ""}. ` : ""}
        {r.endpoints.toLocaleString()} endpoints{cfg.profile.mix ? ` (${describeMix(cfg.profile.mix)})` : ""}, {cfg.profile.users.toLocaleString()} users.{quote.preparedBy ? ` Prepared by ${quote.preparedBy}.` : ""}
      </Paragraph>
      <Stats
        items={[
          { label: "Monthly", value: money(r.monthlyNet, 0) },
          { label: "Annual recurring", value: money(r.annualRecurring, 0) },
          { label: "One-time", value: money(r.oneTime, 0) },
          { label: "Year 1 total", value: money(r.year1Total, 0), hint: r.tax > 0 ? `incl. ${money(r.tax, 0)} tax` : undefined },
          { label: "Annual maintenance (from year 2)", value: r.amcAnnual > 0 ? money(r.amcAnnual, 0) : "—" },
          { label: "3-year total cost of ownership", value: money(r.threeYearTotal, 0) },
        ]}
      />

      <Section title="What's included">
        <DataTable
          columns={[{ label: "Item", width: "34%" }, { label: "Detail", width: "36%" }, { label: "Monthly", width: "15%", align: "right" }, { label: "One-time", width: "15%", align: "right" }]}
          rows={[
            ...r.lines.map((l) => [l.label, l.detail, l.monthly ? money(l.monthly) : "—", l.oneTime ? money(l.oneTime, 0) : "—"]),
            ...discounts.filter(([, v]) => v > 0).map(([label, v]) => [label, "", `-${money(v)}`, ""]),
            ["Total", "", money(r.monthlyNet), money(r.oneTime, 0)],
          ]}
        />
      </Section>

      <Section title="Service levels">
        {plan ? (
          <KeyValues
            items={[
              ["Analyst coverage", `${plan.coverage}${cfg.ai.mode !== "none" ? ", AI first response around the clock" : ""}`],
              ...(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).filter((s) => plan.ackMinutes[s] != null).map((s): [string, string] => [`Acknowledge ${s.toLowerCase()}`, `within ${formatMinutes(plan.ackMinutes[s])}`]),
              ["Incident response retainer", `${(plan.irRetainerHours ?? 0) + cfg.services.irExtraHours} h / year`],
            ]}
          />
        ) : (
          <Paragraph muted>No service plan on this quote.</Paragraph>
        )}
      </Section>

      <Section title="Protection coverage">
        <DataTable
          columns={[{ label: "Control", width: "40%" }, { label: "Covered", width: "15%" }, { label: "By", width: "45%" }]}
          rows={r.coverage.map((c) => [CONTROLS.find((x) => x.key === c.control)?.label ?? c.control, c.covered ? "Yes" : "No", c.by.join(", ") || (c.essential ? "client to provide" : "")])}
        />
      </Section>

      <Section title="Assumptions">
        <Bullets items={assumptions} />
      </Section>

      {company.quoteTerms ? (
        <Section title="Terms">
          <View>
            <Paragraph>{company.quoteTerms}</Paragraph>
          </View>
        </Section>
      ) : null}
      {company.legalName || company.address || company.taxId ? (
        <Section title="Issued by">
          <KeyValues items={[["Company", company.legalName || company.name], ["Address", company.address], ["Tax / VAT number", company.taxId], ["Contact", company.email]]} />
        </Section>
      ) : null}
    </PdfDocument>
  );
}
