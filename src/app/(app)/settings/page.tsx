import Link from "next/link";
import { Bot, Building2, Calculator, Crosshair, FlaskConical, Globe2, KeyRound, LockKeyhole, Mail, MonitorSmartphone, Users } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { getSetting } from "@/lib/settings";
import { PLATFORM_SECRETS, platformSecretStatus, type PlatformSecret } from "@/lib/platform-secrets";
import { domainWhitelist } from "@/lib/forensics/body";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { CompanyForm, EnvironmentControl, ForensicsSettingsForm, SecretsPanel, SiteForm } from "@/components/settings/settings-forms";
import { SecuritySettings } from "@/components/settings/security-settings";
import { SSO } from "@/lib/sso";
import { keyReport } from "@/lib/keys";

const ELSEWHERE = [
  { href: "/ai", icon: Bot, title: "AI agents", text: "Providers (online and local models), agent profiles, autonomy and the kill switch" },
  { href: "/mitre", icon: Crosshair, title: "Detectors", text: "Switch SIEM detectors on and off, under ATT&CK coverage" },
  { href: "/threat-intel", icon: Globe2, title: "Threat feeds", text: "Enable and import public blocklists" },
  { href: "/pricing", icon: Calculator, title: "Pricing setup", text: "Service plans, price book, discounts and exchange rates" },
  { href: "/team", icon: Users, title: "Team & roles", text: "Accounts, roles and security domains" },
];

export default async function SettingsPage() {
  const user = await pageGuard("settings.manage");
  const [company, environment, testClients, secrets, thresholds, allowDomains, site, mfa, ssoOnly, staffWithoutMfa, keys] = await Promise.all([
    getSetting("company.profile"),
    getSetting("platform.environment"),
    db.tenant.count({ where: { isTest: true } }),
    platformSecretStatus(),
    getSetting("forensics.thresholds"),
    getSetting("forensics.allowDomains"),
    getSetting("site.public"),
    getSetting("security.mfa"),
    getSetting("security.ssoOnlyForStaff"),
    db.user.count({ where: { active: true, tenantId: null, mfaEnabledAt: null } }),
    keyReport(),
  ]);
  const rows = (Object.keys(PLATFORM_SECRETS) as PlatformSecret[]).map((name) => ({ name, ...PLATFORM_SECRETS[name], status: secrets[name] }));

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><FlaskConical className="size-4" /> Environment</CardTitle>
          <CardDescription>Whether this database serves real clients or holds test data.</CardDescription>
        </CardHeader>
        <CardContent>
          <EnvironmentControl environment={environment} testClients={testClients} canChange={user.role === "ADMIN"} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><LockKeyhole className="size-4" /> Sign-in and encryption</CardTitle>
          <CardDescription>Two-step sign-in, single sign-on for staff, and how stored credentials are encrypted.</CardDescription>
        </CardHeader>
        <CardContent>
          <SecuritySettings mfa={mfa} ssoOnlyForStaff={ssoOnly} sso={SSO?.name ?? null} staffWithoutMfa={staffWithoutMfa} keys={keys} canEdit isAdmin={user.role === "ADMIN"} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Building2 className="size-4" /> Company profile</CardTitle>
          <CardDescription>Your own details as the service provider. Quotes and reports use them; nothing is filled in for you.</CardDescription>
        </CardHeader>
        <CardContent>
          <CompanyForm initial={company} canEdit />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><MonitorSmartphone className="size-4" /> Public website</CardTitle>
          <CardDescription>The home page and price estimator prospective clients see. Its name and contact details come from the company profile above.</CardDescription>
        </CardHeader>
        <CardContent>
          <SiteForm initial={site} canEdit />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><KeyRound className="size-4" /> Intelligence and chat keys</CardTitle>
          <CardDescription>
            Keys saved here are encrypted (AES-256-GCM) and take precedence over the environment variables. Only the last four characters are ever shown again.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SecretsPanel rows={rows} canEdit />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Mail className="size-4" /> Email &amp; file forensics</CardTitle>
          <CardDescription>Verdict thresholds and the link domains forensics never analyzes.</CardDescription>
        </CardHeader>
        <CardContent>
          <ForensicsSettingsForm thresholds={thresholds} allowDomains={allowDomains} builtIn={domainWhitelist()} canEdit />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Elsewhere</CardTitle>
          <CardDescription>Settings that live next to what they control.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {ELSEWHERE.map((e) => (
            <Link key={e.href} href={e.href} className="flex items-start gap-3 rounded-lg border p-3 transition-colors hover:bg-accent">
              <e.icon className="mt-0.5 size-4 text-muted-foreground" />
              <span>
                <span className="block text-sm font-medium">{e.title}</span>
                <span className="block text-xs text-muted-foreground">{e.text}</span>
              </span>
            </Link>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
