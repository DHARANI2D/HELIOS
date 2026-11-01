import { Bot, CheckCheck, FileSearch, Loader2, Unlock, Wrench } from "lucide-react";

import type { FinalAnalysis } from "@/lib/ai/final-analysis";
import { ACTION_STATUS_LABEL, ACTION_STATUS_VARIANT } from "@/lib/response/labels";
import { formatDateTime } from "@/lib/format";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Markdown } from "@/components/shared/markdown";
import { ActionDecision } from "@/components/approvals/action-decision";
import { AcknowledgeFinalAnalysis, ReanalyseCase, ReviewFinalAnalysis } from "@/components/cases/final-analysis-controls";

// The final analysis HELIOS writes on its own for a case: what happened,
// what's contained, when to lift it and how to remediate. People review it;
// lifting and remediation steps that HELIOS can carry out are actions here
// that wait for a person's approval.

export interface FinalAnalysisReport {
  id: string;
  version: number;
  status: string;
  createdAt: Date;
  reviewedByName: string | null;
  reviewedAt: Date | null;
  reviewNote: string | null;
  clientSeenByName: string | null;
  clientSeenAt: Date | null;
  body: unknown;
}

interface Props {
  caseId: string;
  report: FinalAnalysisReport | null;
  versions: number;
  analysisStatus: string | null;
  // Status of each response action on the case, by id.
  actionStatus: Record<string, string>;
  isClient: boolean;
  canDecide: boolean;
  canReview: boolean;
  canAcknowledge: boolean;
  canReanalyse: boolean;
}

const VERDICT: Record<string, { label: string; tone: string }> = {
  true_positive: { label: "True positive", tone: "text-destructive" },
  suspicious: { label: "Suspicious", tone: "text-warning-ink" },
  benign: { label: "Benign", tone: "text-success-ink" },
  false_positive: { label: "False positive", tone: "text-success-ink" },
  needs_investigation: { label: "Needs investigation", tone: "text-info-ink" },
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-2">
      <h3 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">{title}</h3>
      {children}
    </section>
  );
}

function ActionState({ id, actionStatus, canDecide }: { id: string | null; actionStatus: Record<string, string>; canDecide: boolean }) {
  if (!id) return null;
  const status = actionStatus[id];
  if (!status) return null;
  if (status === "PENDING_APPROVAL" && canDecide) return <ActionDecision actionId={id} />;
  return <Badge variant={ACTION_STATUS_VARIANT[status] ?? "outline"}>{ACTION_STATUS_LABEL[status] ?? status}</Badge>;
}

export function FinalAnalysisPanel({ caseId, report, versions, analysisStatus, actionStatus, isClient, canDecide, canReview, canAcknowledge, canReanalyse }: Props) {
  const running = analysisStatus === "running";
  if (!report) {
    if (!running && analysisStatus !== "failed") return null;
    return (
      <Card className="border-chart-4/25">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            {running ? <Loader2 className="size-4 animate-spin text-chart-4" /> : <Bot className="size-4 text-chart-4" />} Final analysis
          </CardTitle>
          <CardDescription>
            {running
              ? "HELIOS is collecting the logs from the client's tools and investigating the case. The analysis appears here when it's done."
              : "HELIOS couldn't finish the analysis of this case. The reason is in the audit log."}
          </CardDescription>
        </CardHeader>
        {canReanalyse && !isClient && (
          <CardContent>
            <ReanalyseCase caseId={caseId} initialStatus={analysisStatus} />
          </CardContent>
        )}
      </Card>
    );
  }

  const a = report.body as FinalAnalysis;
  const verdict = VERDICT[a.verdict] ?? { label: a.verdict.replaceAll("_", " "), tone: "" };
  const scope = [
    ...a.scope.hosts.map((v) => ["Host", v]),
    ...a.scope.users.map((v) => ["Account", v]),
    ...a.scope.ips.map((v) => ["Address", v]),
    ...a.scope.files.map((v) => ["File", v]),
    ...a.scope.emails.map((v) => ["Sender", v]),
  ];
  const sweep = a.evidence;
  const waiting = [...a.lift.map((l) => l.actionId), ...a.remediation.map((r) => r.actionId)].filter((id): id is string => !!id && actionStatus[id] === "PENDING_APPROVAL").length;

  return (
    <Card id="final-analysis" className="scroll-mt-20 border-chart-4/30">
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="flex flex-col gap-1">
            <CardTitle className="flex items-center gap-2 text-base">
              <FileSearch className="size-4 text-chart-4" /> Final analysis
              <Badge variant="ai">HELIOS</Badge>
              <Badge variant="outline">v{report.version}{versions > 1 ? ` of ${versions}` : ""}</Badge>
              {report.status === "reviewed" ? (
                <Badge variant="success"><CheckCheck /> Reviewed</Badge>
              ) : (
                <Badge variant="warning">Ready for review</Badge>
              )}
            </CardTitle>
            <CardDescription>
              Written by HELIOS on {formatDateTime(report.createdAt)} from the client&apos;s own logs
              {a.basedOn ? ` (${a.basedOn.engine}${a.basedOn.model ? `, ${a.basedOn.model}` : ""})` : ""}.
              {waiting ? ` ${waiting} step${waiting === 1 ? "" : "s"} wait for approval below.` : ""}
            </CardDescription>
          </div>
          {canReanalyse && !isClient && <ReanalyseCase caseId={caseId} initialStatus={analysisStatus} />}
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-5 text-sm">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div>
            <div className="text-xs text-muted-foreground">Verdict</div>
            <div className={`font-semibold ${verdict.tone}`}>{verdict.label}</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">Confidence</div>
            <div className="font-semibold">{Math.round(a.confidence * 100)}%</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">Evidence</div>
            <div className="font-semibold">{sweep ? `${sweep.events.toLocaleString("en-IN")} events` : "Case events only"}</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">Still contained</div>
            <div className="font-semibold">{a.containment.filter((c) => c.status === "EXECUTED").length}</div>
          </div>
        </div>

        <Section title="Summary">
          <p className="whitespace-pre-wrap">{a.summary}</p>
          <p><span className="text-muted-foreground">Root cause: </span>{a.rootCause}</p>
        </Section>

        {a.narrative && (
          <details className="rounded-md border p-3">
            <summary className="cursor-pointer text-sm font-medium">Full report</summary>
            <div className="mt-2"><Markdown>{a.narrative}</Markdown></div>
          </details>
        )}

        {scope.length > 0 && (
          <Section title="Scope">
            <div className="flex flex-wrap gap-1.5">
              {scope.slice(0, 40).map(([k, v]) => (
                <Badge key={`${k}:${v}`} variant="soft" className="max-w-full font-mono text-[11px]">
                  <span className="font-sans text-muted-foreground">{k}</span> <span className="truncate">{v}</span>
                </Badge>
              ))}
            </div>
          </Section>
        )}

        {a.timeline.length > 0 && (
          <Section title="What happened">
            <ol className="flex flex-col gap-1.5 border-l pl-4">
              {a.timeline.map((t, i) => (
                <li key={i} className="relative">
                  <span className="absolute top-1.5 -left-[21px] size-2 rounded-full bg-chart-4" />
                  <span className="font-mono text-xs text-muted-foreground">{t.at}</span> {t.what}
                </li>
              ))}
            </ol>
          </Section>
        )}

        {a.findings.length > 0 && (
          <Section title="Findings">
            <ul className="list-disc space-y-1 pl-5">
              {a.findings.map((f, i) => (
                <li key={i}>
                  {f.finding}
                  {f.evidence.length > 0 && <span className="text-xs text-muted-foreground"> ({f.evidence.length} cited)</span>}
                </li>
              ))}
            </ul>
          </Section>
        )}

        {a.techniques.length > 0 && (
          <Section title="Techniques">
            <div className="flex flex-wrap gap-1.5">
              {a.techniques.map((t) => (
                <Badge key={t.id} variant="outline"><span className="font-mono">{t.id}</span> {t.name}</Badge>
              ))}
            </div>
          </Section>
        )}

        {a.containment.length > 0 && (
          <Section title="Containment">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Action</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>By</TableHead>
                  <TableHead className="text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {a.containment.map((c, i) => (
                  <TableRow key={i}>
                    <TableCell>{c.action}</TableCell>
                    <TableCell className="max-w-56 truncate font-mono text-xs">{c.target ?? "—"}</TableCell>
                    <TableCell>{c.by === "AI" ? <Badge variant="ai">AI</Badge> : "Person"}</TableCell>
                    <TableCell className="text-right"><Badge variant={ACTION_STATUS_VARIANT[c.status] ?? "outline"}>{ACTION_STATUS_LABEL[c.status] ?? c.status}</Badge></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Section>
        )}

        {a.lift.length > 0 && (
          <Section title="Lifting containment">
            <p className="text-xs text-muted-foreground">HELIOS never lifts containment on its own. Approve each one when its conditions hold.</p>
            <div className="flex flex-col gap-2">
              {a.lift.map((l, i) => (
                <div key={i} className="flex flex-wrap items-start justify-between gap-3 rounded-md border p-3">
                  <div className="flex min-w-0 flex-1 flex-col gap-1">
                    <div className="flex items-center gap-2 font-medium">
                      <Unlock className="size-4 text-muted-foreground" /> Lift {l.action.toLowerCase()} <span className="truncate font-mono text-xs">{l.target}</span>
                      {l.now && <Badge variant="success">Safe to lift now</Badge>}
                    </div>
                    <ul className="list-disc pl-5 text-xs text-muted-foreground">
                      {l.conditions.map((c, j) => <li key={j}>{c}</li>)}
                    </ul>
                  </div>
                  <ActionState id={l.actionId} actionStatus={actionStatus} canDecide={canDecide} />
                </div>
              ))}
            </div>
          </Section>
        )}

        {a.remediation.length > 0 && (
          <Section title="Remediation plan">
            <div className="flex flex-col gap-2">
              {a.remediation.map((r, i) => (
                <div key={i} className="flex flex-wrap items-start justify-between gap-3 rounded-md border p-3">
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <div className="flex items-center gap-2 font-medium">
                      <Wrench className="size-4 text-muted-foreground" /> {r.step}
                    </div>
                    <div className="text-xs text-muted-foreground">Why: {r.why}. Owner: {r.owner}.</div>
                  </div>
                  <ActionState id={r.actionId} actionStatus={actionStatus} canDecide={canDecide} />
                </div>
              ))}
            </div>
          </Section>
        )}

        {sweep && (
          <Section title="Logs collected">
            <p className="text-xs text-muted-foreground">
              From {formatDateTime(sweep.window.from)} to {formatDateTime(sweep.window.to)}, across this client&apos;s connected tools; {sweep.attached.toLocaleString("en-IN")} event(s) attached to the case.
            </p>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Log type</TableHead>
                  <TableHead>Client tools</TableHead>
                  <TableHead className="text-right">Events</TableHead>
                  <TableHead className="text-right">Needed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sweep.logTypes.map((t) => (
                  <TableRow key={t.type}>
                    <TableCell>{t.label}</TableCell>
                    <TableCell className="max-w-56 truncate text-xs">{t.sources.join(", ") || <span className="text-muted-foreground">None connected</span>}</TableCell>
                    <TableCell className="text-right tabular-nums">{t.events.toLocaleString("en-IN")}</TableCell>
                    <TableCell className="text-right">
                      {t.needed ? (t.events || t.sources.length ? <Badge variant="soft">Yes</Badge> : <Badge variant="warning">Missing</Badge>) : <span className="text-xs text-muted-foreground">—</span>}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {sweep.gaps.length > 0 && (
              <ul className="list-disc pl-5 text-xs text-warning-ink">
                {sweep.gaps.map((g) => <li key={g.type}>{g.why}.</li>)}
              </ul>
            )}
            {!isClient && sweep.refreshed.some((r) => !r.ok) && (
              <p className="text-xs text-muted-foreground">
                Couldn&apos;t refresh: {sweep.refreshed.filter((r) => !r.ok).map((r) => `${r.source} (${r.stream})`).join(", ")}.
              </p>
            )}
          </Section>
        )}

        {a.openQuestions.length > 0 && (
          <Section title="Open questions">
            <ul className="list-disc space-y-1 pl-5">
              {a.openQuestions.map((q, i) => <li key={i}>{q}</li>)}
            </ul>
          </Section>
        )}

        <div className="flex flex-col gap-2 border-t pt-4">
          {report.status === "reviewed" ? (
            <p className="text-xs text-muted-foreground">
              Reviewed by {report.reviewedByName ?? "the SOC"}{report.reviewedAt ? ` on ${formatDateTime(report.reviewedAt)}` : ""}{report.reviewNote ? `: ${report.reviewNote}` : "."}
            </p>
          ) : canReview && !isClient ? (
            <ReviewFinalAnalysis reportId={report.id} />
          ) : (
            <p className="text-xs text-muted-foreground">Waiting for the SOC&apos;s review.</p>
          )}
          {report.clientSeenAt ? (
            <p className="text-xs text-muted-foreground">Acknowledged by {report.clientSeenByName ?? "the client"} on {formatDateTime(report.clientSeenAt)}.</p>
          ) : isClient && canAcknowledge ? (
            <div><AcknowledgeFinalAnalysis reportId={report.id} /></div>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}
