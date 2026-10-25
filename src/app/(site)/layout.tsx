import Link from "next/link";
import { FlaskConical, Mail, MapPin, Phone, ShieldHalf } from "lucide-react";

import { auth } from "@/lib/auth";
import { platformEnvironment } from "@/lib/settings";
import { companyProfile, siteSettings } from "@/lib/site";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/shell/theme-toggle";

// The public website's frame: the MSSP's name and contact details from
// Settings → Company, and a way into the console.
export default async function SiteLayout({ children }: LayoutProps<"/">) {
  const [session, company, site, environment] = await Promise.all([auth(), companyProfile(), siteSettings(), platformEnvironment()]);
  const brand = company.name.trim() || "HELIOS";
  const website = company.website.trim();

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-40 border-b bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/65">
        <div className="mx-auto flex h-14 max-w-6xl items-center gap-3 px-4 sm:px-6">
          <Link href="/home" className="flex items-center gap-2 font-semibold tracking-tight">
            <span className="flex size-7 items-center justify-center rounded-md bg-primary text-primary-foreground">
              <ShieldHalf className="size-4" />
            </span>
            <span className="truncate">{brand}</span>
          </Link>
          <nav aria-label="Site" className="ml-4 hidden items-center gap-1 text-sm text-muted-foreground md:flex">
            <Link href="/home#surface" className="rounded-md px-2.5 py-1.5 hover:bg-accent hover:text-foreground">What we protect</Link>
            <Link href="/home#how" className="rounded-md px-2.5 py-1.5 hover:bg-accent hover:text-foreground">How it works</Link>
            <Link href="/home#ai" className="rounded-md px-2.5 py-1.5 hover:bg-accent hover:text-foreground">AI first response</Link>
            {site.estimator && <Link href="/home#plans" className="rounded-md px-2.5 py-1.5 hover:bg-accent hover:text-foreground">Plans</Link>}
            <Link href="/home#integrations" className="rounded-md px-2.5 py-1.5 hover:bg-accent hover:text-foreground">Integrations</Link>
          </nav>
          <div className="ml-auto flex items-center gap-2">
            <ThemeToggle className="hidden sm:inline-flex" />
            {site.estimator && (
              <Button asChild size="sm" variant="outline" className="hidden sm:inline-flex">
                <Link href="/estimate">Estimate your price</Link>
              </Button>
            )}
            <Button asChild size="sm">
              <Link href={session ? "/" : "/login"}>{session ? "Open console" : "Sign in"}</Link>
            </Button>
          </div>
        </div>
      </header>

      {environment === "test" && (
        <div role="status" className="border-b border-warning/40 bg-warning/15">
          <p className="mx-auto flex max-w-6xl items-center gap-2 px-4 py-1.5 text-xs sm:px-6">
            <FlaskConical className="size-3.5 shrink-0" />
            <span><strong>Test environment.</strong> Plans, prices and tools on this site are test data.</span>
          </p>
        </div>
      )}

      <main className="flex-1">{children}</main>

      <footer className="border-t bg-muted/30">
        <div className="mx-auto grid max-w-6xl gap-6 px-4 py-10 text-sm sm:px-6 md:grid-cols-[1fr_auto]">
          <div className="flex flex-col gap-2">
            <p className="flex items-center gap-2 font-semibold">
              <ShieldHalf className="size-4 text-primary" /> {company.legalName.trim() || brand}
            </p>
            <ul className="flex flex-col gap-1 text-muted-foreground">
              {company.address.trim() && (
                <li className="flex items-start gap-2"><MapPin className="mt-0.5 size-3.5 shrink-0" /> <span className="whitespace-pre-line">{company.address}</span></li>
              )}
              {company.email.trim() && (
                <li className="flex items-center gap-2"><Mail className="size-3.5 shrink-0" /> <a href={`mailto:${company.email}`} className="hover:text-foreground hover:underline">{company.email}</a></li>
              )}
              {company.phone.trim() && (
                <li className="flex items-center gap-2"><Phone className="size-3.5 shrink-0" /> <a href={`tel:${company.phone.replace(/[^+\d]/g, "")}`} className="hover:text-foreground hover:underline">{company.phone}</a></li>
              )}
            </ul>
          </div>
          <div className="flex flex-col gap-2 text-muted-foreground md:items-end">
            <div className="flex flex-wrap gap-x-4 gap-y-1">
              {site.estimator && <Link href="/estimate" className="hover:text-foreground">Estimator</Link>}
              <Link href={session ? "/" : "/login"} className="hover:text-foreground">{session ? "Console" : "Client & staff sign-in"}</Link>
              {website && /^https?:\/\//i.test(website) && <a href={website} className="hover:text-foreground" rel="noopener">{website.replace(/^https?:\/\//i, "")}</a>}
            </div>
            <ThemeToggle className="sm:hidden" />
            <p className="text-xs">© {new Date().getFullYear()} {company.legalName.trim() || brand}{company.taxId.trim() ? ` · ${company.taxId}` : ""}</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
