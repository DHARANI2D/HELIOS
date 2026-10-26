import { Radar, SlidersHorizontal, Upload } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { getSetting } from "@/lib/settings";
import { formatDateTime } from "@/lib/format";
import { DETECTORS } from "@/lib/siem/engine";
import { TUNING_FIELDS, TUNING_KINDS, TUNING_OPS } from "@/lib/detections/tuning";
import { DetectorToggle } from "@/components/mitre/detector-toggle";
import { RemoveTuning, RuleControls } from "@/components/detections/rule-controls";
import { SigmaImport } from "@/components/detections/sigma-import";
import { TuningForm } from "@/components/detections/tuning-form";
import { StatTile } from "@/components/dashboard/stat-tile";
import { TestBadge } from "@/components/shared/test-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const STATUS_VARIANT = { ACTIVE: "success", TESTING: "warning", DISABLED: "outline" } as const;
const STATUS_LABEL = { ACTIVE: "Live", TESTING: "Testing", DISABLED: "Disabled" } as const;

// Detection engineering: the built-in detectors, imported Sigma rules
// (tested before they go live), and per-client tuning of both.
export default async function DetectionsPage() {
  await pageGuard("detections.tune");
  const [disabled, rules, tunings, tenants, recent] = await Promise.all([
    getSetting("detection.disabledDetectors"),
    db.detectionRule.findMany({ orderBy: [{ status: "asc" }, { title: "asc" }] }),
    db.detectionTuning.findMany({ include: { tenant: { select: { name: true, isTest: true } } }, orderBy: { createdAt: "desc" } }),
    db.tenant.findMany({ where: { status: { not: "SUSPENDED" } }, select: { id: true, name: true }, orderBy: { name: "asc" } }),
    db.detection.groupBy({ by: ["ruleId"], where: { source: "SIGMA_RULE", createdAt: { gte: new Date(new Date().setUTCHours(0, 0, 0, 0) - 6 * 86_400_000) } }, _count: true }),
  ]);
  const tenantName = new Map(tenants.map((t) => [t.id, t.name]));
  const liveHits = new Map(recent.map((r) => [r.ruleId, r._count]));
  const targets = [
    ...DETECTORS.map((d) => ({ value: d.name, label: `Built-in: ${d.name}` })),
    ...rules.map((r) => ({ value: `sigma:${r.sigmaId}`, label: `Sigma: ${r.title}` })),
  ];
  const targetLabel = (t: string) => (t === "*" ? "Every detector and rule" : targets.find((x) => x.value === t)?.label ?? t);
  const now = new Date();

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatTile label="Built-in detectors on" value={`${DETECTORS.length - disabled.length} of ${DETECTORS.length}`} icon={Radar} />
        <StatTile label="Sigma rules" value={rules.length} icon={Upload} hint={`${rules.filter((r) => r.status === "ACTIVE").length} live · ${rules.filter((r) => r.status === "TESTING").length} testing`} />
        <StatTile label="Tuning in force" value={tunings.filter((t) => !t.expiresAt || t.expiresAt > now).length} icon={SlidersHorizontal} hint={`${tunings.reduce((n, t) => n + t.hits, 0).toLocaleString()} findings held back so far`} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Built-in detectors</CardTitle>
          <CardDescription>The correlation and behaviour detectors that run on every batch of telemetry. Switching one off here applies to every client; tune it for one client below.</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Detector</TableHead>
                <TableHead>What it finds</TableHead>
                <TableHead>Techniques</TableHead>
                <TableHead className="text-right">On</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {DETECTORS.map((d) => (
                <TableRow key={d.name} className="align-top">
                  <TableCell className="text-xs font-medium">{d.name}</TableCell>
                  <TableCell className="max-w-md whitespace-normal text-xs text-muted-foreground">{d.description}</TableCell>
                  <TableCell className="whitespace-normal font-mono text-[11px]">{d.techniques.join(" ")}</TableCell>
                  <TableCell className="text-right"><DetectorToggle name={d.name} enabled={!disabled.includes(d.name)} canTune /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Sigma rules</CardTitle>
          <CardDescription>Imported rules run on every new batch. In testing they only count what they match, with samples; once live, a match raises a detection that correlates into cases like the built-in ones.</CardDescription>
        </CardHeader>
        <CardContent>
          {rules.length === 0 ? (
            <p className="text-sm text-muted-foreground">No Sigma rules yet. Import some below; the SigmaHQ repository is the usual starting point.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Rule</TableHead>
                  <TableHead>For</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Matches</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((r) => {
                  const samples = (r.samples as string[] | null) ?? [];
                  return (
                    <TableRow key={r.id} className="align-top">
                      <TableCell className="max-w-md whitespace-normal text-xs">
                        <p className="font-medium">{r.title} <Badge variant="outline" className="ml-1">{r.level}</Badge></p>
                        <p className="font-mono text-[11px] text-muted-foreground">{r.logsource} · {r.techniques.join(" ") || "no ATT&CK tags"}</p>
                        {r.warnings.map((w, i) => <p key={i} className="text-warning-ink">{w}</p>)}
                        <details className="mt-1">
                          <summary className="cursor-pointer text-muted-foreground">YAML{samples.length ? " and samples" : ""}</summary>
                          <pre className="mt-1 max-h-60 overflow-auto rounded bg-muted p-2 text-[11px]">{r.yaml}</pre>
                          {samples.length > 0 && <ul className="mt-1 font-mono text-[11px]">{samples.map((s, i) => <li key={i} className="truncate">{s}</li>)}</ul>}
                        </details>
                      </TableCell>
                      <TableCell className="text-xs">{r.tenantId ? tenantName.get(r.tenantId) ?? "A client" : "Every client"}</TableCell>
                      <TableCell><Badge variant={STATUS_VARIANT[r.status]}>{STATUS_LABEL[r.status]}</Badge></TableCell>
                      <TableCell className="text-xs tabular">
                        {r.status === "ACTIVE" ? `${liveHits.get(`sigma:${r.sigmaId}`) ?? 0} detections in 7 days` : `${r.testHits.toLocaleString()} test matches`}
                        {r.lastHitAt && <p className="text-muted-foreground">last {formatDateTime(r.lastHitAt)}</p>}
                      </TableCell>
                      <TableCell className="text-right"><RuleControls id={r.id} status={r.status} informational={r.level === "informational"} /></TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Import Sigma rules</CardTitle>
          <CardDescription>
            Paste rules, check them and backtest them against the last 7 days of events, then import. They start in testing. A rule HELIOS can&apos;t evaluate faithfully (aggregations, correlation rules, fieldref, unknown modifiers) is refused with the reason rather than run with part of its logic missing.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SigmaImport tenants={tenants} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Tuning by client</CardTitle>
          <CardDescription>Leave out events known to be fine at one client, switch a detector or rule off there, or set the severity it raises. Every entry needs a reason, can expire, and counts what it held back, so stale tuning shows up.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-6">
          {tunings.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Client</TableHead>
                  <TableHead>Applies to</TableHead>
                  <TableHead>Tuning</TableHead>
                  <TableHead>Why</TableHead>
                  <TableHead>Held back</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {tunings.map((t) => {
                  const expired = t.expiresAt && t.expiresAt <= now;
                  return (
                    <TableRow key={t.id} className={expired ? "opacity-60" : undefined}>
                      <TableCell className="text-xs">{t.tenant.name}{t.tenant.isTest && <TestBadge className="ml-1" />}</TableCell>
                      <TableCell className="max-w-56 whitespace-normal text-xs">{targetLabel(t.target)}</TableCell>
                      <TableCell className="text-xs whitespace-normal">
                        {t.kind === "exclude" ? `Leave out where ${TUNING_FIELDS[t.field as keyof typeof TUNING_FIELDS]?.toLowerCase() ?? t.field} ${TUNING_OPS[t.op as keyof typeof TUNING_OPS] ?? t.op} "${t.value}"` : t.kind === "severity" ? `Severity ${t.severity?.toLowerCase()}` : TUNING_KINDS.disable}
                        {t.expiresAt && <p className="text-muted-foreground">{expired ? "expired" : "until"} {formatDateTime(t.expiresAt)}</p>}
                      </TableCell>
                      <TableCell className="max-w-72 whitespace-normal text-xs text-muted-foreground">{t.reason}</TableCell>
                      <TableCell className="text-xs tabular">{t.hits.toLocaleString()}{t.lastHitAt && <p className="text-muted-foreground">last {formatDateTime(t.lastHitAt)}</p>}</TableCell>
                      <TableCell className="text-right"><RemoveTuning id={t.id} /></TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
          <TuningForm tenants={tenants} targets={targets} />
        </CardContent>
      </Card>
    </div>
  );
}
