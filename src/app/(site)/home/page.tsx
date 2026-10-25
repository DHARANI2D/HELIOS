import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import {
  ArrowRight,
  BellRing,
  Bot,
  Calculator,
  Check,
  Cloud,
  Cpu,
  FileCheck2,
  HardDrive,
  KeyRound,
  Link2,
  Lock,
  ScrollText,
  ShieldCheck,
  Sparkles,
  UserCheck,
  Users,
  Workflow,
} from "lucide-react";

import { loadHomeData, companyProfile } from "@/lib/site";
import { CONTROLS } from "@/lib/endpoints/controls";
import { AGENT_TYPES, AGENT_KEYS } from "@/lib/ai/catalog";
import { PLAN_FEATURES, PLAN_FEATURE_LABEL, formatMinutes } from "@/lib/plans";
import { formatMoney } from "@/lib/pricing/calculator";
import { ROLES, ROLE_ORDER } from "@/lib/rbac";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

export async function generateMetadata(): Promise<Metadata> {
  const company = await companyProfile();
  const brand = company.name.trim() || "HELIOS";
  return { title: { absolute: `${brand} · Managed detection & response` }, description: `${brand}: managed detection and response with AI first response and analyst-led investigation.` };
}

const STEPS = [
  { icon: Link2, title: "Connect your tools", body: "We onboard the security tools you already run, or the ones we recommend. Their alerts flow into one queue; their response actions become one click for our analysts." },
  { icon: Bot, title: "AI first response", body: "An AI agent triages every new alert the moment it lands: verdict, confidence, the evidence behind it, and the containment it recommends, within the autonomy you allow." },
  { icon: UserCheck, title: "Analysts investigate", body: "A human analyst does the primary analysis on every case, confirms or overrides the AI, contains the threat and escalates to incident response when needed." },
  { icon: FileCheck2, title: "You stay in control", body: "Your portal shows every case and what was done about it. Your admins can approve containment on your estate, AI never acts beyond the autonomy you consent to, and monthly service reports are a click away." },
];

const TRUST = [
  { icon: ScrollText, title: "Tamper-evident audit trail", body: "Every action, by a person or an AI agent, is written to a hash-chained audit log that auditors can verify and export." },
  { icon: Lock, title: "Credentials sealed at rest", body: "Tool API keys and webhooks are encrypted with AES-256-GCM; ingest and API tokens are stored only as hashes." },
  { icon: ShieldCheck, title: "Guardrails on AI", body: "A per-client consent cap, a platform kill switch, a confidence bar for automatic containment, and actions like disabling a user always need a human." },
  { icon: KeyRound, title: "Least-privilege access", body: "Each role sees what it needs: triage, analysis, incident response, hunting, detection engineering, audit, and your own team's client view." },
];

export default async function HomePage() {
  const data = await loadHomeData();
  if (!data.site.enabled) redirect("/login");
  const { site, brand, stats, plans, categories } = data;
  const showPrices = site.estimator;
  const pricedPlans = plans.filter((p) => p.pricePerEndpoint != null);
  const fastestCritical = plans.map((p) => p.ackMinutes.CRITICAL).filter((m): m is number => m != null).sort((a, b) => a - b)[0];
  const fromPrice = pricedPlans.map((p) => p.pricePerEndpoint!).sort((a, b) => a - b)[0];
  const headline = site.headline.trim() || "Managed detection and response, with AI first response on every alert";
  const intro =
    site.intro.trim() ||
    `${brand} watches your endpoints, email and identities. AI agents triage each alert as it lands and start containment within the limits you set; a human analyst does the primary analysis and sees it through.`;

  return (
    <div className="flex flex-col">
      {/* Hero */}
      <section className="relative overflow-hidden border-b">
        <div aria-hidden className="pointer-events-none absolute inset-0 bg-[radial-gradient(60%_80%_at_15%_0%,var(--glow),transparent_70%),radial-gradient(40%_60%_at_95%_20%,color-mix(in_oklch,var(--chart-2)_14%,transparent),transparent_70%)]" />
        <div className="relative mx-auto grid max-w-6xl gap-10 px-4 py-16 sm:px-6 md:py-24 lg:grid-cols-[1.15fr_1fr] lg:items-center">
          <div className="flex flex-col gap-6">
            <Badge variant="info" className="gap-1.5"><Sparkles /> AI first response · analyst-led</Badge>
            <h1 className="text-4xl font-semibold tracking-tight text-balance sm:text-5xl">{headline}</h1>
            <p className="max-w-xl text-lg text-pretty text-muted-foreground">{intro}</p>
            <div className="flex flex-wrap gap-3">
              {site.estimator && (
                <Button asChild size="lg">
                  <Link href="/estimate"><Calculator /> Estimate your price</Link>
                </Button>
              )}
              <Button asChild size="lg" variant="outline">
                <Link href="#how">How it works <ArrowRight /></Link>
              </Button>
            </div>
            {showPrices && fromPrice != null && (
              <p className="text-sm text-muted-foreground">Managed service from <span className="font-semibold text-foreground">{formatMoney(fromPrice, "USD", 1)}</span> per endpoint per month.</p>
            )}
          </div>

          <dl className="grid grid-cols-2 gap-3">
            {[
              { value: stats.techniques.toLocaleString("en-US"), label: `MITRE ATT&CK techniques detected, across ${stats.tactics} of ${stats.totalTactics} tactics` },
              { value: stats.tools.toLocaleString("en-US"), label: `security tools from ${stats.vendors} vendors ready to onboard` },
              { value: stats.withResponse.toLocaleString("en-US"), label: "of them take response actions from our SOC: isolate, block, quarantine" },
              fastestCritical != null
                ? { value: `≤ ${formatMinutes(fastestCritical)}`, label: "to acknowledge a critical alert, on our fastest plan" }
                : { value: AGENT_KEYS.length.toString(), label: "AI agent types, each on the model you choose" },
            ].map((s) => (
              <div key={s.label} className="rounded-xl border bg-card/80 p-4 shadow-xs backdrop-blur">
                <dt className="sr-only">{s.label}</dt>
                <dd className="text-3xl font-semibold tracking-tight tabular">{s.value}</dd>
                <dd className="mt-1 text-xs text-muted-foreground">{s.label}</dd>
              </div>
            ))}
          </dl>
        </div>
      </section>

      {/* How it works */}
      <section id="how" className="scroll-mt-16 border-b">
        <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
          <SectionHeading eyebrow="How it works" title="From alert to contained, with a human in the loop" />
          <ol className="mt-10 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {STEPS.map((s, i) => (
              <li key={s.title} className="flex flex-col gap-3 rounded-xl border bg-card p-5">
                <div className="flex items-center gap-3">
                  <span className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary"><s.icon className="size-4.5" /></span>
                  <span className="text-xs font-medium text-muted-foreground">Step {i + 1}</span>
                </div>
                <h3 className="font-semibold">{s.title}</h3>
                <p className="text-sm text-muted-foreground">{s.body}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      {/* Endpoint protection */}
      <section className="border-b bg-muted/20">
        <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
          <SectionHeading
            eyebrow="Endpoint protection"
            title="Every layer a well-protected device needs"
            body="We track each of your endpoints against these controls and show the gaps. Essential controls are the baseline we hold every managed device to."
          />
          <ul className="mt-10 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {CONTROLS.map((c) => (
              <li key={c.key} className="flex gap-3 rounded-lg border bg-card p-4">
                <span className="mt-0.5 flex h-6 min-w-11 items-center justify-center rounded bg-muted px-1.5 font-mono text-[10px] font-semibold">{c.short}</span>
                <div className="min-w-0">
                  <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
                    {c.label}
                    {c.essential && <Badge variant="soft" className="text-[10px]">essential</Badge>}
                  </p>
                  <p className="text-xs text-muted-foreground">{c.description}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* AI */}
      <section id="ai" className="scroll-mt-16 border-b">
        <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
          <SectionHeading
            eyebrow="AI first response"
            title="AI agents that work for our analysts, on the model you choose"
            body="Every finding cites the evidence it rests on, and every AI decision is recorded. Run the agents online, or keep everything inside your network."
          />
          <div className="mt-10 grid gap-4 md:grid-cols-3">
            {[
              { icon: Cloud, title: "Cloud", body: "Claude, with nothing to host. Pay per alert analyzed." },
              { icon: HardDrive, title: "Local / offline", body: "Your own GPU hardware running an open model (Ollama, LM Studio, vLLM). Alert data never leaves your network." },
              { icon: Cpu, title: "Rules only", body: "No model at all: a deterministic engine triages and reports. Also the fallback if a model is unavailable." },
            ].map((o) => (
              <div key={o.title} className="flex flex-col gap-2 rounded-xl border bg-card p-5">
                <o.icon className="size-5 text-primary" />
                <h3 className="font-semibold">{o.title}</h3>
                <p className="text-sm text-muted-foreground">{o.body}</p>
              </div>
            ))}
          </div>
          <div className="mt-8 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {AGENT_KEYS.map((k) => (
              <div key={k} className="rounded-lg border p-4">
                <p className="flex items-center gap-2 text-sm font-medium"><Bot className="size-4 text-chart-4" /> {AGENT_TYPES[k].name}</p>
                <p className="mt-1 text-xs text-muted-foreground">{AGENT_TYPES[k].description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Plans */}
      {showPrices && plans.length > 0 && (
        <section id="plans" className="scroll-mt-16 border-b bg-muted/20">
          <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
            <SectionHeading eyebrow="Plans" title="Pick the coverage you need" body="Per endpoint per month for the managed service. Tool licences, onboarding and AI options are priced in the estimator for your size." />
            <div className={`mt-10 grid gap-4 ${plans.length >= 3 ? "lg:grid-cols-3" : "md:grid-cols-2"}`}>
              {plans.map((p) => (
                <div key={p.key} className="flex flex-col gap-4 rounded-xl border bg-card p-6">
                  <div>
                    <h3 className="text-lg font-semibold">{p.name}</h3>
                    {p.tagline && <p className="text-sm text-muted-foreground">{p.tagline}</p>}
                  </div>
                  <p>
                    {p.pricePerEndpoint == null ? (
                      <span className="text-sm text-muted-foreground">Priced on request</span>
                    ) : (
                      <>
                        <span className="text-3xl font-semibold tracking-tight tabular">{formatMoney(p.pricePerEndpoint, "USD", 1)}</span>
                        <span className="text-sm text-muted-foreground"> / endpoint / month</span>
                      </>
                    )}
                  </p>
                  <ul className="flex flex-col gap-1.5 text-sm">
                    <li className="flex items-center gap-2"><BellRing className="size-4 text-muted-foreground" /> {p.coverage} analyst coverage</li>
                    {(["CRITICAL", "HIGH", "MEDIUM"] as const).map((s) =>
                      p.ackMinutes[s] != null ? (
                        <li key={s} className="flex items-center gap-2 text-muted-foreground"><Check className="size-4 text-success-ink" /> {s.charAt(0) + s.slice(1).toLowerCase()} alerts acknowledged in ≤ {formatMinutes(p.ackMinutes[s])}</li>
                      ) : null,
                    )}
                    {p.irRetainerHours > 0 && <li className="flex items-center gap-2 text-muted-foreground"><Check className="size-4 text-success-ink" /> {p.irRetainerHours} h incident response per year</li>}
                    {PLAN_FEATURES.filter((f) => p.features[f]).map((f) => (
                      <li key={f} className="flex items-center gap-2 text-muted-foreground">
                        <Check className="size-4 text-success-ink" /> {PLAN_FEATURE_LABEL[f]}
                        {typeof p.features[f] === "string" ? ` (${p.features[f]})` : ""}
                      </li>
                    ))}
                  </ul>
                  <Button asChild variant="outline" className="mt-auto">
                    <Link href={`/estimate?plan=${encodeURIComponent(p.key)}`}>Estimate with {p.name}</Link>
                  </Button>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {/* Integrations */}
      <section id="integrations" className="scroll-mt-16 border-b">
        <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
          <SectionHeading
            eyebrow="Integrations"
            title="Bring your stack, or let us recommend one"
            body={`${stats.tools} tools across ${categories.length} categories. Tools marked "alerts" stream detections to our SOC; "response" means our analysts can act through them.${stats.offline ? ` ${stats.offline} work fully offline.` : ""}`}
          />
          <div className="mt-10 grid gap-4 md:grid-cols-2">
            {categories.map((c) => (
              <div key={c.key} className="rounded-xl border bg-card p-5">
                <p className="text-sm font-semibold">{c.label}</p>
                <p className="text-xs text-muted-foreground">{c.description}</p>
                <ul className="mt-3 flex flex-wrap gap-1.5">
                  {c.tools.map((t) => (
                    <li key={t.key} className="inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs">
                      {t.label}
                      {t.alerts && <span className="text-[10px] text-info-ink">· alerts</span>}
                      {t.actions > 0 && <span className="text-[10px] text-success-ink">· response</span>}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Trust */}
      <section className="border-b bg-muted/20">
        <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
          <SectionHeading eyebrow="Trust" title="Built to be audited" />
          <div className="mt-10 grid gap-4 md:grid-cols-2">
            {TRUST.map((t) => (
              <div key={t.title} className="flex gap-4 rounded-xl border bg-card p-5">
                <t.icon className="mt-0.5 size-5 shrink-0 text-primary" />
                <div>
                  <h3 className="font-semibold">{t.title}</h3>
                  <p className="text-sm text-muted-foreground">{t.body}</p>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-8 rounded-xl border bg-card p-5">
            <p className="flex items-center gap-2 text-sm font-semibold"><Users className="size-4 text-primary" /> A view for every role</p>
            <ul className="mt-3 grid gap-x-6 gap-y-2 text-xs sm:grid-cols-2 lg:grid-cols-3">
              {ROLE_ORDER.filter((r) => r !== "ADMIN").map((r) => (
                <li key={r}>
                  <span className="font-medium">{ROLES[r].label}</span>
                  <span className="block text-muted-foreground">{ROLES[r].description}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      {/* CTA */}
      {site.estimator && (
        <section>
          <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
            <div className="surface-glow flex flex-col items-start gap-4 rounded-2xl border bg-card p-8 md:flex-row md:items-center md:justify-between">
              <div>
                <h2 className="flex items-center gap-2 text-2xl font-semibold tracking-tight"><Workflow className="size-5 text-primary" /> See your price in two minutes</h2>
                <p className="mt-1 text-muted-foreground">Enter your endpoints by type and the tools you run today. Get a monthly and annual estimate, upgrade options with their price difference, and a suggested stack.</p>
              </div>
              <Button asChild size="lg">
                <Link href="/estimate">Open the estimator <ArrowRight /></Link>
              </Button>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}

function SectionHeading({ eyebrow, title, body }: { eyebrow: string; title: string; body?: string }) {
  return (
    <div className="max-w-2xl">
      <p className="text-sm font-medium text-primary">{eyebrow}</p>
      <h2 className="mt-1 text-3xl font-semibold tracking-tight text-balance">{title}</h2>
      {body && <p className="mt-3 text-muted-foreground text-pretty">{body}</p>}
    </div>
  );
}
