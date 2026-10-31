import { ListChecks } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { CASE_SOURCES, matchSchema, parseSteps } from "@/lib/runbooks/match";
import { InstallTemplates, RunbookEditor, RunbookRow, type RunbookDraft } from "@/components/runbooks/runbook-editor";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

// Runbooks: written procedures that attach themselves to the cases they
// match and are worked as a checklist on the case.
export default async function RunbooksPage() {
  const user = await pageGuard("operations.view");
  const canEdit = can(user, "operations.manage");
  const [runbooks, tenants, usage] = await Promise.all([
    db.runbook.findMany({ orderBy: [{ enabled: "desc" }, { title: "asc" }], include: { _count: { select: { cases: true } } } }),
    db.tenant.findMany({ where: { status: { not: "SUSPENDED" } }, select: { id: true, name: true }, orderBy: { name: "asc" } }),
    db.caseRunbook.groupBy({ by: ["runbookId"], where: { completedAt: { not: null } }, _count: true }),
  ]);
  const completed = new Map(usage.map((u) => [u.runbookId, u._count]));
  const tenantName = new Map(tenants.map((t) => [t.id, t.name]));

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-4">
          <div>
            <CardTitle className="flex items-center gap-2 text-base"><ListChecks className="size-4" /> Runbooks</CardTitle>
            <CardDescription>
              Procedures for analysts. A runbook attaches itself to the cases it matches (by ATT&amp;CK technique or title words, narrowed by source and severity; a client&apos;s own runbooks first, at most three per case) and is worked as a checklist on the case. A case keeps the version it got.
            </CardDescription>
          </div>
          {canEdit && <InstallTemplates />}
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {runbooks.length === 0 && <p className="text-sm text-muted-foreground">No runbooks yet.{canEdit ? " Add the starter runbooks (phishing, compromised account, malware, ransomware, data exfiltration) and adapt them, or write your own below." : ""}</p>}
          {runbooks.map((r) => {
            const m = matchSchema.safeParse(r.match);
            const steps = parseSteps(r.steps);
            const draft: RunbookDraft = { id: r.id, tenantId: r.tenantId, title: r.title, description: r.description ?? "", match: m.success ? m.data : { sources: [], techniques: [], keywords: [], minSeverity: null }, steps };
            return (
              <RunbookRow key={r.id} draft={draft} enabled={r.enabled} tenants={tenants} canEdit={canEdit}>
                <p className="text-sm font-medium">
                  {r.title} <span className="text-xs font-normal text-muted-foreground">v{r.version}</span>
                  {r.tenantId && <Badge variant="soft" className="ml-1">{tenantName.get(r.tenantId) ?? "A client"}</Badge>}
                  {!r.enabled && <Badge variant="outline" className="ml-1">off</Badge>}
                </p>
                {r.description && <p className="text-xs text-muted-foreground">{r.description}</p>}
                <p className="mt-1 text-xs">
                  {m.success ? [m.data.techniques.length ? <span key="t" className="font-mono">{m.data.techniques.join(" ")}</span> : null, m.data.keywords.length ? `"${m.data.keywords.join('", "')}"` : null, m.data.sources.length ? m.data.sources.map((s) => CASE_SOURCES[s]).join(", ") : null, m.data.minSeverity ? `${m.data.minSeverity.toLowerCase()} and above` : null].filter(Boolean).reduce<React.ReactNode[]>((acc, x, i) => (i ? [...acc, " · ", x] : [x]), []) : "Unreadable match rules"}
                </p>
                <p className="text-xs text-muted-foreground">{steps.length} steps ({steps.filter((s) => s.required).length} required) · on {r._count.cases} case{r._count.cases === 1 ? "" : "s"}, completed on {completed.get(r.id) ?? 0}</p>
              </RunbookRow>
            );
          })}
        </CardContent>
      </Card>

      {canEdit && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">New runbook</CardTitle>
          </CardHeader>
          <CardContent><RunbookEditor tenants={tenants} /></CardContent>
        </Card>
      )}
    </div>
  );
}
