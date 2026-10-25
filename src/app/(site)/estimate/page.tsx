import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { companyProfile, platformFacts, publicPricingContext, siteSettings } from "@/lib/site";
import { publicConfig } from "@/lib/pricing/public";
import { defaultQuoteConfig } from "@/lib/pricing/calculator";
import { EMPTY_MIX } from "@/lib/pricing/endpoint-mix";
import { Estimator } from "@/components/site/estimator";

export async function generateMetadata(): Promise<Metadata> {
  const company = await companyProfile();
  return { title: { absolute: `Estimate your price · ${company.name.trim() || "HELIOS"}` } };
}

export default async function EstimatePage({ searchParams }: PageProps<"/estimate">) {
  const [site, company, sp] = await Promise.all([siteSettings(), companyProfile(), searchParams]);
  if (!site.enabled) redirect("/login");
  if (!site.estimator) redirect("/home");
  const [ctx, facts] = await Promise.all([publicPricingContext(), platformFacts()]);
  const wanted = Array.isArray(sp.plan) ? sp.plan[0] : sp.plan;
  const base = defaultQuoteConfig(ctx);
  const initial = publicConfig({ ...base, plan: ctx.plans.some((p) => p.key === wanted) ? wanted! : base.plan, profile: { ...base.profile, mix: EMPTY_MIX } }, ctx);

  return (
    <Estimator
      ctx={ctx}
      initial={initial}
      brand={company.name.trim() || "HELIOS"}
      aiAdvisor={site.aiAdvisor}
      leads={site.leads}
      contactEmail={company.email.trim() || null}
      facts={facts}
    />
  );
}
