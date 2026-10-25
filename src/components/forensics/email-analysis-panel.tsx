import type { Case } from "@prisma/client";

import type { ForensicsMetadata } from "@/lib/forensics/service";
import type { AttachmentAnalysis } from "@/lib/forensics/files";
import { MX_CHECKS } from "@/lib/forensics/mxtoolbox";
import { formatBytes } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { DetonationView } from "@/components/forensics/detonation-view";

const AUTH_VARIANT = (status: string) =>
  status === "pass" ? "success" : status === "fail" || status === "softfail" ? "destructive" : "outline";

const RISK_VARIANT = { Malicious: "destructive", "High Risk": "destructive", Suspicious: "warning", Clean: "secondary" } as const;

function AttachmentCard({ a, nested = false }: { a: AttachmentAnalysis; nested?: boolean }) {
  return (
    <div className={nested ? "ml-4 border-l pl-3" : "rounded-md border p-3"}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium break-all">{a.filename}</span>
        <Badge variant={RISK_VARIANT[a.risk]}>{a.risk}</Badge>
        <span className="text-xs text-muted-foreground">{a.fileType} · {formatBytes(a.size)} · entropy {a.entropy} · +{a.score}</span>
      </div>
      <p className="mt-1 font-mono text-[11px] text-muted-foreground break-all">SHA-256 {a.sha256}</p>
      {a.reasons.length > 0 && (
        <ul className="mt-2 list-disc space-y-0.5 pl-5 text-xs">
          {a.reasons.map((r, i) => <li key={i}>{r}</li>)}
        </ul>
      )}
      {a.techniques.length > 0 && <p className="mt-1 font-mono text-[11px]">{a.techniques.join(", ")}</p>}
      {a.pe && (
        <p className="mt-1 text-xs text-muted-foreground">
          PE {a.pe.machine}{a.pe.compileTime ? `, compiled ${a.pe.compileTime.slice(0, 10)}` : ""} · sections {a.pe.sections.map((s) => `${s.name}(${s.entropy})`).join(" ")}
        </p>
      )}
      {a.urls.length > 0 && (
        <p className="mt-1 text-xs">Embedded links: {a.urls.map((u) => <span key={u} className="mr-2 font-mono break-all">{u}</span>)}</p>
      )}
      {a.archiveEntries && a.archiveEntries.length > 0 && (
        <p className="mt-1 text-xs text-muted-foreground">Archive: {a.archiveEntries.map((e) => `${e.name}${e.encrypted ? " 🔒" : ""}`).join(", ")}</p>
      )}
      {a.image && (a.image.qr.length > 0 || a.image.text || a.image.error) && (
        <div className="mt-2 rounded-md bg-muted/50 p-2 text-xs">
          <p className="text-muted-foreground">Image {a.image.width}×{a.image.height}</p>
          {a.image.qr.map((q) => <p key={q}>QR code: <span className="font-mono break-all">{q}</span></p>)}
          {a.image.text && (
            <details className="mt-1">
              <summary className="cursor-pointer">Text read from the image ({a.image.text.length} characters)</summary>
              <p className="mt-1 whitespace-pre-wrap font-mono text-[11px]">{a.image.text}</p>
            </details>
          )}
          {a.image.error && <p className="text-muted-foreground">{a.image.error}</p>}
        </div>
      )}
      {a.children?.map((c) => <div key={c.sha256 + c.filename} className="mt-2"><AttachmentCard a={c} nested /></div>)}
    </div>
  );
}

export function EmailAnalysisPanel({ kase }: { kase: Case }) {
  const meta = kase.metadata as unknown as ForensicsMetadata | null;
  if (!meta?.verdict) return null;
  const { verdict, email, headers, body, attachments, sandbox } = meta;
  const maxPoints = Math.max(1, ...verdict.breakdown.map((b) => b.points));

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Verdict: <span className="capitalize">{verdict.verdict}</span> · score {verdict.totalScore}</CardTitle>
          <CardDescription>{verdict.explanation}</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="flex flex-col gap-2" aria-label="Score breakdown">
            {verdict.breakdown.map((b) => (
              <div key={b.component}>
                <div className="flex justify-between text-xs">
                  <span>{b.component}</span>
                  <span className="tabular-nums text-muted-foreground">+{b.points}</span>
                </div>
                <div className="mt-1 h-2 rounded-full bg-muted">
                  <div className="h-2 rounded-full bg-primary" style={{ width: `${(b.points / maxPoints) * 100}%` }} />
                </div>
              </div>
            ))}
          </div>
          {meta.blockRecommendations.length > 0 && (
            <div>
              <p className="text-xs font-medium text-muted-foreground">Block recommendations</p>
              <ul className="mt-1 space-y-0.5 font-mono text-xs break-all">
                {meta.blockRecommendations.map((r) => <li key={r}>{r}</li>)}
              </ul>
            </div>
          )}
        </CardContent>
      </Card>

      {email && headers && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Message & sender</CardTitle>
              <CardDescription>{email.format === "msg" ? "Outlook .msg — headers from the transport header block" : "RFC 822 message"}</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-3 text-sm">
              <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-xs">
                <dt className="text-muted-foreground">From</dt><dd className="break-all">{email.from ?? "—"}</dd>
                <dt className="text-muted-foreground">Reply-To</dt><dd className="break-all">{email.replyTo ?? "—"}</dd>
                <dt className="text-muted-foreground">Return-Path</dt><dd className="break-all">{headers.returnPath ?? "—"}</dd>
                <dt className="text-muted-foreground">To</dt><dd className="break-all">{email.to ?? "—"}</dd>
                <dt className="text-muted-foreground">Date</dt><dd>{email.date ?? "—"}</dd>
                <dt className="text-muted-foreground">Sender IP</dt><dd className="font-mono">{headers.senderIp ?? "—"}</dd>
              </dl>
              <div className="flex flex-wrap gap-1.5">
                <Badge variant={AUTH_VARIANT(headers.auth.spf.status)}>SPF {headers.auth.spf.status}</Badge>
                <Badge variant={AUTH_VARIANT(headers.auth.dkim.status)}>DKIM {headers.auth.dkim.status}</Badge>
                <Badge variant={AUTH_VARIANT(headers.auth.dmarc.status)}>DMARC {headers.auth.dmarc.status}</Badge>
                <Badge variant="outline">{headers.auth.tls.version}</Badge>
              </div>
              {headers.reasons.length > 0 && (
                <ul className="list-disc space-y-0.5 pl-5 text-xs">{headers.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Delivery path</CardTitle>
              <CardDescription>Received headers, first hop first.</CardDescription>
            </CardHeader>
            <CardContent>
              {headers.hops.length === 0 ? (
                <p className="text-sm text-muted-foreground">No Received headers.</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>#</TableHead>
                      <TableHead>From</TableHead>
                      <TableHead>IP</TableHead>
                      <TableHead className="text-right">Delay</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {headers.hops.map((h) => (
                      <TableRow key={h.hop} className="text-xs">
                        <TableCell>{h.hop}</TableCell>
                        <TableCell className="max-w-48 truncate" title={`${h.from} → ${h.by ?? ""}`}>{h.from}</TableCell>
                        <TableCell className="font-mono">{h.ip ?? "—"}</TableCell>
                        <TableCell className="text-right tabular-nums">{h.delaySeconds !== undefined ? `${h.delaySeconds}s` : "—"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {meta.mxtoolbox && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Sender domain diagnostics</CardTitle>
            <CardDescription>MxToolbox checks for {headers?.fromAddress?.split("@")[1]}.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex flex-wrap gap-1.5">
              {MX_CHECKS.map((check) => {
                const r = meta.mxtoolbox![check];
                return (
                  <Badge key={check} variant={!r.checked ? "outline" : r.passed ? "success" : "destructive"}>
                    {check.toUpperCase()} {!r.checked ? "not checked" : r.passed ? "pass" : "fail"}
                  </Badge>
                );
              })}
            </div>
            <ul className="space-y-0.5 text-xs">
              {MX_CHECKS.flatMap((check) =>
                meta.mxtoolbox![check].details
                  .filter((d) => d.status === "FAIL")
                  .map((d, i) => (
                    <li key={`${check}-${i}`}>
                      <span className="font-medium">{check.toUpperCase()}</span> · {d.name}{d.info ? `: ${d.info}` : ""}
                    </li>
                  )),
              )}
            </ul>
          </CardContent>
        </Card>
      )}

      {body && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Body & links</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 text-sm">
            {body.reasons.length > 0 ? (
              <ul className="list-disc space-y-0.5 pl-5 text-xs">{body.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
            ) : (
              <p className="text-xs text-muted-foreground">No content indicators.</p>
            )}
            {body.urls.length > 0 && (
              <div>
                <p className="text-xs font-medium text-muted-foreground">Links ({body.urls.length})</p>
                <ul className="mt-1 space-y-0.5 font-mono text-xs break-all">{body.urls.map((u) => <li key={u}>{u}</li>)}</ul>
              </div>
            )}
            {body.whitelistedHits.length > 0 && <p className="text-xs text-muted-foreground">Whitelisted (not analyzed): {body.whitelistedHits.join(", ")}</p>}
            {email?.bodyPreview && (
              <details>
                <summary className="cursor-pointer text-xs text-muted-foreground">Plain-text body</summary>
                <pre className="mt-2 max-h-64 overflow-auto rounded-md bg-muted/40 p-3 text-xs whitespace-pre-wrap">{email.bodyPreview}</pre>
              </details>
            )}
          </CardContent>
        </Card>
      )}

      {attachments.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{meta.kind === "email" ? `Attachments (${attachments.length})` : "File forensics"}</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {attachments.map((a) => <AttachmentCard key={a.sha256 + a.filename} a={a} />)}
          </CardContent>
        </Card>
      )}

      {(sandbox.length > 0 || meta.detonationRequested) && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">URL detonation</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {sandbox.length === 0 ? <p className="text-sm text-muted-foreground">No non-whitelisted links to detonate.</p> : sandbox.map((s) => <DetonationView key={s.url} result={s} />)}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
