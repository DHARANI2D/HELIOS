import Link from "next/link";
import { Ban, Download, Fingerprint, Globe2, ShieldAlert, TriangleAlert } from "lucide-react";
import type { IndicatorType, Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { configuredProviders } from "@/lib/threat-intel/providers";
import { indicatorVerdict } from "@/lib/threat-intel/service";
import { formatRelative } from "@/lib/format";
import { StatTile } from "@/components/dashboard/stat-tile";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyState } from "@/components/shared/empty-state";
import { Pagination, parsePage } from "@/components/shared/pagination";
import { LookupForm } from "@/components/threat-intel/lookup-form";
import { BlockToggle } from "@/components/threat-intel/block-toggle";
import { RecheckButton } from "@/components/threat-intel/recheck-button";
import { VerdictBadge } from "@/components/threat-intel/verdict-badge";

const PAGE_SIZE = 30;
const TYPES: IndicatorType[] = ["IP", "DOMAIN", "URL", "FILE_HASH", "EMAIL_ADDRESS"];
const PROVIDERS = [
  { id: "virustotal", label: "VirusTotal", env: "VIRUSTOTAL_API_KEY", types: "IP, domain, URL, file hash" },
  { id: "abuseipdb", label: "AbuseIPDB", env: "ABUSEIPDB_API_KEY", types: "IP" },
] as const;

function one(v: string | string[] | undefined) {
  return Array.isArray(v) ? v[0] : v;
}

export default async function ThreatIntelPage({ searchParams }: PageProps<"/threat-intel">) {
  const user = await pageGuard("intel.view");
  const canManage = can(user, "intel.manage");
  const sp = await searchParams;
  const page = parsePage(sp.page);
  const type = TYPES.find((t) => t === one(sp.type));
  const risk = one(sp.risk);
  const q = one(sp.q)?.trim() || undefined;

  const where: Prisma.ThreatIndicatorWhereInput = {};
  if (type) where.type = type;
  if (q) where.value = { contains: q, mode: "insensitive" };
  if (risk === "malicious") where.maliciousScore = { gte: 0.7 };
  if (risk === "suspicious") where.maliciousScore = { gte: 0.4 };
  if (risk === "blocked") where.blockedAt = { not: null };

  const configured = new Set(configuredProviders());

  const [indicators, total, tracked, malicious, suspicious, blocked] = await Promise.all([
    db.threatIndicator.findMany({
      where,
      orderBy: [{ maliciousScore: { sort: "desc", nulls: "last" } }, { lastCheckedAt: "desc" }],
      skip: (page - 1) * PAGE_SIZE,
      take: PAGE_SIZE,
      include: { _count: { select: { caseLinks: true } } },
    }),
    db.threatIndicator.count({ where }),
    db.threatIndicator.count(),
    db.threatIndicator.count({ where: { maliciousScore: { gte: 0.7 } } }),
    db.threatIndicator.count({ where: { maliciousScore: { gte: 0.4, lt: 0.7 } } }),
    db.threatIndicator.count({ where: { blockedAt: { not: null } } }),
  ]);

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="Indicators tracked" value={tracked} icon={Fingerprint} />
        <StatTile label="Malicious" value={malicious} icon={ShieldAlert} tone={malicious > 0 ? "critical" : "default"} />
        <StatTile label="Suspicious" value={suspicious} icon={TriangleAlert} tone={suspicious > 0 ? "warning" : "default"} />
        <StatTile label="On blocklist" value={blocked} icon={Ban} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Indicator lookup</CardTitle>
            <CardDescription>
              One shared IOC cache for every module. Provider answers are cached for 24h; built-in intel (known C2 / Tor
              ranges, suspicious TLDs, brand impersonation) always applies.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <LookupForm />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Providers</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 text-sm">
            <div className="flex items-center justify-between">
              <span>Built-in intel</span>
              <Badge variant="success">Active</Badge>
            </div>
            {PROVIDERS.map((p) => (
              <div key={p.id} className="flex items-start justify-between gap-2">
                <div>
                  <p>{p.label}</p>
                  <p className="text-xs text-muted-foreground">{p.types}</p>
                </div>
                {configured.has(p.id) ? (
                  <Badge variant="success">Configured</Badge>
                ) : (
                  <Badge variant="outline" title={`Set ${p.env} to enable`}>Set {p.env}</Badge>
                )}
              </div>
            ))}
            <Button variant="outline" size="sm" asChild className="mt-2">
              <a href="/api/threat-intel/blocklist">
                <Download /> Download blocklist
              </a>
            </Button>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Indicator store</CardTitle>
          <CardDescription>Everything extracted from SIEM telemetry, investigations, and analyzed emails, plus manual lookups.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <form className="flex flex-wrap items-center gap-2" action="/threat-intel">
            <Input name="q" defaultValue={q} placeholder="Search value…" className="w-64" />
            <NativeSelect name="type" defaultValue={type ?? ""} aria-label="Type">
              <option value="">All types</option>
              {TYPES.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </NativeSelect>
            <NativeSelect name="risk" defaultValue={risk ?? ""} aria-label="Risk">
              <option value="">Any risk</option>
              <option value="malicious">Malicious</option>
              <option value="suspicious">Suspicious or worse</option>
              <option value="blocked">Blocked</option>
            </NativeSelect>
            <Button type="submit" variant="secondary">Filter</Button>
            {(q || type || risk) && (
              <Button variant="ghost" asChild>
                <Link href="/threat-intel">Reset</Link>
              </Button>
            )}
          </form>

          {indicators.length === 0 ? (
            <EmptyState icon={Globe2} title="No indicators" description="Indicators appear as modules extract IOCs, or when you look one up above." />
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Indicator</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Verdict</TableHead>
                    <TableHead className="text-right">Score</TableHead>
                    <TableHead>Sources</TableHead>
                    <TableHead className="text-right">Cases</TableHead>
                    <TableHead>Checked</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {indicators.map((i) => (
                    <TableRow key={i.id}>
                      <TableCell className="max-w-sm truncate font-mono text-xs" title={i.value}>{i.value}</TableCell>
                      <TableCell className="text-xs">{i.type}</TableCell>
                      <TableCell><VerdictBadge verdict={indicatorVerdict(i)} /></TableCell>
                      <TableCell className="text-right tabular-nums">{i.maliciousScore != null ? i.maliciousScore.toFixed(2) : "—"}</TableCell>
                      <TableCell className="text-xs">{i.sources.join(", ") || "—"}</TableCell>
                      <TableCell className="text-right tabular-nums">{i._count.caseLinks}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatRelative(i.lastCheckedAt)}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <RecheckButton indicatorId={i.id} />
                          {canManage ? <BlockToggle indicatorId={i.id} blocked={!!i.blockedAt} /> : i.blockedAt ? <Badge variant="outline">Blocked</Badge> : null}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <Pagination page={page} pageSize={PAGE_SIZE} total={total} basePath="/threat-intel" params={{ q, type, risk }} />
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
