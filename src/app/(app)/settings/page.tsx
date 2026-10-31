import Link from "next/link";
import { BellRing, Bot, Building2, Calculator, Crosshair, FlaskConical, Globe2, KeyRound, LockKeyhole, Mail, MapPin, MonitorSmartphone, Users } from "lucide-react";

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
import { channelStatus } from "@/lib/alerts/send";
import { deliveryCounts } from "@/lib/alerts/outbox";
import { AlertChannels } from "@/components/settings/alert-channels";
import { geoStatus } from "@/lib/geoip";

const ELSEWHERE = [
  { href: "/ai", icon: Bot, title: "AI agents", text: "Providers (online and local models), agent profiles, autonomy and the kill switch" },
  { href: "/mitre", icon: Crosshair, title: "Detectors", text: "Switch SIEM detectors on and off, under ATT&CK coverage" },
  { href: "/threat-intel", icon: Globe2, title: "Threat feeds", text: "Enable and import public blocklists" },
  { href: "/pricing", icon: Calculator, title: "Pricing setup", text: "Service plans, price book, discounts and exchange rates" },
  { href: "/team", icon: Users, title: "Team & roles", text: "Accounts, roles and security domains" },
];

export default async function SettingsPage() {
  const user = await pageGuard("settings.manage");
  const [company, environment, testClients, secrets, thresholds, allowDomains, site, mfa, ssoOnly, staffWithoutMfa, keys, messaging, ready, deliveries] = await Promise.all([
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
    getSetting("alerts.messaging"),
    channelStatus(),
    deliveryCounts(),
  ]);
  const rows = (Object.keys(PLATFORM_SECRETS) as PlatformSecret[]).map((name) => ({ name, ...PLATFORM_SECRETS[name], status: secrets[name] }));
  const geo = geoStatus();

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
          <CardTitle className="flex items-center gap-2 text-base"><BellRing className="size-4" /> Alert channels</CardTitle>
          <CardDescription>How alerts reach people outside HELIOS: email, SMS and WhatsApp. Each person picks theirs under My alerts; client approver chains use them too.</CardDescription>
        </CardHeader>
        <CardContent>
          <AlertChannels initial={messaging} ready={ready} counts={deliveries} canEdit />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><KeyRound className="size-4" /> Provider keys</CardTitle>
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
          <CardTitle className="flex items-center gap-2 text-base"><MapPin className="size-4" /> IP geolocation</CardTitle>
          <CardDescription>
            Where event and indicator addresses are, from MaxMind-format databases on the server (looked up locally, never sent anywhere). It adds the country,
            city and network to ingested events and sharpens impossible-travel detection.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2 text-sm">
          {[
            { label: "City or country database", env: "HELIOS_GEOIP_CITY_DB", db: geo.city },
            { label: "Network (ASN) database", env: "HELIOS_GEOIP_ASN_DB", db: geo.asn },
          ].map((r) => (
            <p key={r.env}>
              <span className="font-medium">{r.label}: </span>
              {r.db?.type ? (
                <span>{r.db.type}, built {r.db.built?.slice(0, 10)}</span>
              ) : r.db ? (
                <span className="text-destructive">{r.db.path} can&apos;t be read</span>
              ) : (
                <span className="text-muted-foreground">not set (<code>{r.env}</code>)</span>
              )}
            </p>
          ))}
          <p className="text-xs text-muted-foreground">
            MaxMind GeoLite2 (free with an account; keep it current with geoipupdate) or DB-IP&apos;s Lite databases (CC BY 4.0) both work.
            {geo.attribution ? ` ${geo.attribution}.` : ""}
          </p>
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
