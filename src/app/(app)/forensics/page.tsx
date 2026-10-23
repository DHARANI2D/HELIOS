import Link from "next/link";
import { MailWarning } from "lucide-react";

import { db } from "@/lib/db";
import type { ForensicsMetadata } from "@/lib/forensics/service";
import { formatRelative } from "@/lib/format";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge, StatusBadge } from "@/components/shared/case-badges";
import { EmptyState } from "@/components/shared/empty-state";
import { AnalyzeForm } from "@/components/forensics/analyze-form";
import { UrlDetonator } from "@/components/forensics/url-detonator";

export default async function ForensicsPage() {
  const analyses = await db.case.findMany({
    where: { sourceType: "EMAIL_ANALYSIS" },
    orderBy: { createdAt: "desc" },
    take: 50,
  });

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-3">
          <CardHeader>
            <CardTitle className="text-base">Analyze a message or file</CardTitle>
            <CardDescription>
              SPF/DKIM/DMARC and sender-identity checks, phishing-content and link heuristics, attachment forensics (macros, XLM, OLE objects,
              PDF actions, PE packing, archives, polyglots), optional link detonation, and a scored verdict filed as a case.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <AnalyzeForm />
          </CardContent>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">URL detonation</CardTitle>
            <CardDescription>One-off check of a single link — follows redirects and inspects the landing page. No case is filed.</CardDescription>
          </CardHeader>
          <CardContent>
            <UrlDetonator />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent analyses</CardTitle>
        </CardHeader>
        <CardContent>
          {analyses.length === 0 ? (
            <EmptyState icon={MailWarning} title="Nothing analyzed yet" description="Upload an .eml, or try the sample phishing email." />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Subject / file</TableHead>
                  <TableHead>Verdict</TableHead>
                  <TableHead>Threat</TableHead>
                  <TableHead className="text-right">Score</TableHead>
                  <TableHead className="text-right">Attachments</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Analyzed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {analyses.map((c) => {
                  const meta = c.metadata as unknown as ForensicsMetadata | null;
                  return (
                    <TableRow key={c.id}>
                      <TableCell><SeverityBadge severity={c.severity} /></TableCell>
                      <TableCell className="max-w-md">
                        <Link href={`/cases/${c.id}`} className="line-clamp-1 font-medium hover:underline">{c.title}</Link>
                        {meta?.email?.from && <span className="line-clamp-1 text-xs text-muted-foreground">{meta.email.from}</span>}
                      </TableCell>
                      <TableCell className="text-sm capitalize">{c.verdict ?? "—"}</TableCell>
                      <TableCell className="text-xs">{meta?.verdict?.threatType ? `${meta.verdict.threatType} · ${meta.verdict.threatCategory}` : "—"}</TableCell>
                      <TableCell className="text-right tabular-nums">{c.riskScore ?? "—"}</TableCell>
                      <TableCell className="text-right tabular-nums">{meta?.attachments?.length ?? 0}</TableCell>
                      <TableCell><StatusBadge status={c.status} /></TableCell>
                      <TableCell className="text-right text-xs text-muted-foreground">{formatRelative(c.createdAt)}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
