import { headers } from "next/headers";
import { KeyRound } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { formatDateTime } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { CreateTokenForm, RevokeTokenButton } from "@/components/api/token-controls";

const ENDPOINTS: Array<{ method: string; path: string; what: string; needs: string }> = [
  { method: "GET", path: "/api/v1/me", what: "Who the token acts as, and its permissions", needs: "any token" },
  { method: "GET", path: "/api/v1/cases?status=open&severity=HIGH&limit=50", what: "Cases you can see, newest first; page with nextCursor (&cursor=)", needs: "cases.view" },
  { method: "GET", path: "/api/v1/cases/{id}", what: "One case: detections, indicators, ATT&CK, timeline, response actions, comments", needs: "cases.view" },
  { method: "PATCH", path: "/api/v1/cases/{id}", what: '{"status":"RESOLVED","disposition":"TRUE_POSITIVE","note":"why"} · {"severity":"HIGH"} · {"assignee":"analyst@…"}', needs: "write token, cases.triage (cases.assign for others)" },
  { method: "POST", path: "/api/v1/cases/{id}/comments", what: '{"body":"…","clientVisible":false}', needs: "write token, cases.comment" },
  { method: "GET", path: "/api/v1/indicators?value=203.0.113.7", what: "Indicator reputation from the shared store (&refresh=1 asks the providers)", needs: "intel.view" },
  { method: "GET", path: "/api/v1/metrics?range=30d", what: "Service metrics as on the Reports page (or &month=YYYY-MM)", needs: "reports.view" },
];

async function origin() {
  const h = await headers();
  const host = h.get("x-forwarded-host") ?? h.get("host") ?? "localhost:3000";
  const proto = h.get("x-forwarded-proto") ?? (host.startsWith("localhost") ? "http" : "https");
  return `${proto}://${host}`;
}

async function loadTokens(userId: string, admin: boolean) {
  const now = new Date();
  const [mine, others] = await Promise.all([
    db.apiToken.findMany({ where: { userId }, orderBy: { createdAt: "desc" }, take: 50 }),
    admin ? db.apiToken.findMany({ where: { userId: { not: userId }, revokedAt: null, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] }, orderBy: { createdAt: "desc" }, take: 100, include: { user: { select: { email: true, role: true } } } }) : Promise.resolve([]),
  ]);
  return { now, mine, others };
}

export default async function ApiTokensPage() {
  const user = await pageGuard("api.tokens");
  const admin = user.role === "ADMIN";
  const [{ now, mine, others }, base] = await Promise.all([loadTokens(user.id, admin), origin()]);
  const canWriteAnything = can(user, "cases.triage") || can(user, "cases.comment");
  const state = (t: { revokedAt: Date | null; expiresAt: Date | null }) => (t.revokedAt ? "revoked" : t.expiresAt && t.expiresAt < now ? "expired" : "active");

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><KeyRound className="size-4" /> New token</CardTitle>
          <CardDescription>
            A token acts as you: it sees only the cases you can see and does only what your role allows. Read-only unless you switch on write.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <CreateTokenForm canWriteAnything={canWriteAnything} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Your tokens</CardTitle>
        </CardHeader>
        <CardContent>
          {mine.length === 0 ? (
            <p className="text-sm text-muted-foreground">You haven&apos;t created any tokens.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow><TableHead>Name</TableHead><TableHead>Access</TableHead><TableHead>Created</TableHead><TableHead>Last used</TableHead><TableHead>Expires</TableHead><TableHead /></TableRow>
              </TableHeader>
              <TableBody>
                {mine.map((t) => (
                  <TableRow key={t.id} className={state(t) !== "active" ? "opacity-60" : undefined}>
                    <TableCell>
                      <p className="text-sm font-medium">{t.name}</p>
                      <p className="font-mono text-[11px] text-muted-foreground">{t.prefix}…</p>
                    </TableCell>
                    <TableCell>{t.canWrite ? <Badge variant="warning">read &amp; write</Badge> : <Badge variant="outline">read</Badge>}</TableCell>
                    <TableCell className="text-xs">{formatDateTime(t.createdAt)}</TableCell>
                    <TableCell className="text-xs">{t.lastUsedAt ? formatDateTime(t.lastUsedAt) : "Never"}</TableCell>
                    <TableCell className="text-xs">{state(t) === "revoked" ? "Revoked" : t.expiresAt ? formatDateTime(t.expiresAt) : "Never"}</TableCell>
                    <TableCell className="text-right">{state(t) === "active" && <RevokeTokenButton tokenId={t.id} name={t.name} />}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {admin && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Everyone else&apos;s active tokens</CardTitle>
            <CardDescription>As platform admin you can revoke any token.</CardDescription>
          </CardHeader>
          <CardContent>
            {others.length === 0 ? (
              <p className="text-sm text-muted-foreground">No other active tokens.</p>
            ) : (
              <Table>
                <TableHeader><TableRow><TableHead>Owner</TableHead><TableHead>Name</TableHead><TableHead>Access</TableHead><TableHead>Last used</TableHead><TableHead /></TableRow></TableHeader>
                <TableBody>
                  {others.map((t) => (
                    <TableRow key={t.id}>
                      <TableCell className="text-xs">{t.user.email}</TableCell>
                      <TableCell className="text-sm">{t.name} <span className="font-mono text-[11px] text-muted-foreground">{t.prefix}…</span></TableCell>
                      <TableCell>{t.canWrite ? <Badge variant="warning">read &amp; write</Badge> : <Badge variant="outline">read</Badge>}</TableCell>
                      <TableCell className="text-xs">{t.lastUsedAt ? formatDateTime(t.lastUsedAt) : "Never"}</TableCell>
                      <TableCell className="text-right"><RevokeTokenButton tokenId={t.id} name={t.name} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">REST API v1</CardTitle>
          <CardDescription>JSON over HTTPS, authenticated with <code className="font-mono">Authorization: Bearer &lt;token&gt;</code>. 300 requests per minute per token. Errors come back as <code className="font-mono">{"{ \"error\": \"…\" }"}</code> with the matching status.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <Table>
            <TableHeader><TableRow><TableHead className="w-20">Method</TableHead><TableHead>Path</TableHead><TableHead>Returns / body</TableHead><TableHead>Needs</TableHead></TableRow></TableHeader>
            <TableBody>
              {ENDPOINTS.map((e) => (
                <TableRow key={`${e.method} ${e.path}`}>
                  <TableCell><Badge variant={e.method === "GET" ? "outline" : "warning"} className="font-mono">{e.method}</Badge></TableCell>
                  <TableCell className="font-mono text-xs break-all whitespace-normal">{e.path}</TableCell>
                  <TableCell className="text-xs whitespace-normal">{e.what}</TableCell>
                  <TableCell className="text-xs whitespace-normal text-muted-foreground">{e.needs}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <pre className="overflow-x-auto rounded-md bg-muted/50 p-3 font-mono text-xs">{`curl -H "Authorization: Bearer $HELIOS_TOKEN" "${base}/api/v1/cases?status=open&limit=20"

curl -X PATCH -H "Authorization: Bearer $HELIOS_TOKEN" -H "content-type: application/json" \\
  -d '{"status":"RESOLVED","disposition":"BENIGN_TRUE_POSITIVE","note":"Confirmed benign"}' "${base}/api/v1/cases/<case id>"`}</pre>
        </CardContent>
      </Card>
    </div>
  );
}
