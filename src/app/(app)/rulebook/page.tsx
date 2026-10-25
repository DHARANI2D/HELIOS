import Link from "next/link";
import { notFound } from "next/navigation";
import { AlertTriangle, ShieldCheck } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { selectedTenantId } from "@/lib/access";
import { AGENT_TYPES, AUTONOMY_LABEL } from "@/lib/ai/catalog";
import { clientAiSpend, previewClientModels, whyNot } from "@/lib/ai/gateway";
import { assetTypeLabel, endpointClass } from "@/lib/assets/inventory";
import { industryFromText } from "@/lib/assets/estate";
import { formatRelative } from "@/lib/format";
import { diffRulebooks } from "@/lib/rulebook/diff";
import { AI_RESIDENCY, EMPTY_RULEBOOK } from "@/lib/rulebook/schema";
import { buildTemplate, templateFor } from "@/lib/rulebook/templates";
import { parseStored, rulebookReminders, rulebookState } from "@/lib/rulebook/service";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { TestBadge } from "@/components/shared/test-badge";
import { RulebookEditor } from "@/components/rulebook/rulebook-editor";
import { RulebookSummary } from "@/components/rulebook/rulebook-summary";
import { ClientAiPanel } from "@/components/rulebook/client-ai-panel";
import { AllowlistPanel, CodePanel, DraftControls, DryRunPanel, SignPanel } from "@/components/rulebook/rulebook-panels";

const STATUS_LABEL = { DRAFT: "Draft", AWAITING_SIGNATURE: "Awaiting signature", ACTIVE: "In force", SUPERSEDED: "Superseded" } as const;
const STATUS_VARIANT = { DRAFT: "outline", AWAITING_SIGNATURE: "warning", ACTIVE: "success", SUPERSEDED: "secondary" } as const;

function daysAgo(days: number) {
  return new Date(new Date().getTime() - days * 86_400_000);
}

async function ClientList() {
  const tenants = await db.tenant.findMany({
    orderBy: { name: "asc" },
    select: { id: true, name: true, isTest: true, industry: true, policies: { where: { status: { in: ["ACTIVE", "DRAFT", "AWAITING_SIGNATURE"] } }, select: { version: true, status: true, signedAt: true, body: true } } },
  });
  const now = new Date();
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><ShieldCheck className="size-4" /> Client rulebooks</CardTitle>
        <CardDescription>
          Each client&apos;s signed rules for what HELIOS may do on its estate: protected assets and accounts, which actions run automatically, hours, approvers and data handling. The response policy reads them on every decision; they can only restrict what the plan and the client&apos;s AI consent allow.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow><TableHead>Client</TableHead><TableHead>In force</TableHead><TableHead>Pending</TableHead><TableHead>Review</TableHead></TableRow>
          </TableHeader>
          <TableBody>
            {tenants.map((t) => {
              const active = t.policies.find((p) => p.status === "ACTIVE");
              const pending = t.policies.find((p) => p.status !== "ACTIVE");
              const due = active?.signedAt ? new Date(active.signedAt.getTime() + parseStored(active).reviewEveryDays * 86_400_000) : null;
              return (
                <TableRow key={t.id}>
                  <TableCell><Link className="font-medium hover:underline" href={`/rulebook?tenant=${t.id}`}>{t.name}</Link> {t.isTest && <TestBadge />}</TableCell>
                  <TableCell>{active ? <Badge variant="success">v{active.version}</Badge> : <span className="text-xs text-muted-foreground">None — plan and consent only</span>}</TableCell>
                  <TableCell>{pending ? <Badge variant={STATUS_VARIANT[pending.status]}>v{pending.version} {STATUS_LABEL[pending.status].toLowerCase()}</Badge> : "—"}</TableCell>
                  <TableCell className="text-xs">{due ? (due <= now ? <span className="text-destructive">Overdue</span> : `Due ${due.toISOString().slice(0, 10)}`) : "—"}</TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

export default async function RulebookPage({ searchParams }: PageProps<"/rulebook">) {
  const user = await pageGuard("rulebook.view");
  const sp = await searchParams;
  const requested = typeof sp.tenant === "string" ? sp.tenant : null;
  const tenantId = user.isClient ? user.tenantId : (requested ?? (await selectedTenantId(user)));
  if (!tenantId) return <ClientList />;

  const tenant = await db.tenant.findUnique({ where: { id: tenantId }, select: { id: true, name: true, industry: true, isTest: true, aiAutonomyCap: true, plan: { select: { name: true, defaultAutonomyCap: true } } } });
  if (!tenant) notFound();

  const since = daysAgo(30);
  const [state, allowlist, endpoints, accounts, providers, reminders, aiPreview, aiPolicy, aiSpend, aiProviders, me] = await Promise.all([
    rulebookState(tenant.id),
    db.policyAllowlistEntry.findMany({ where: { tenantId: tenant.id }, orderBy: { createdAt: "desc" } }),
    db.endpoint.findMany({ where: { tenantId: tenant.id }, orderBy: { hostname: "asc" }, select: { hostname: true, os: true, assetClass: true, assetType: true, criticality: true }, take: 1000 }),
    db.securityEvent.findMany({ where: { tenantId: tenant.id, userName: { not: null }, timestamp: { gte: since } }, distinct: ["userName"], select: { userName: true }, take: 300 }),
    db.aiProvider.findMany({ where: { enabled: true, OR: [{ tenantId: null }, { tenantId }] }, orderBy: { name: "asc" }, select: { id: true, name: true, isLocal: true } }),
    rulebookReminders(tenant.id),
    previewClientModels(tenant.id, user.id),
    db.tenantAiPolicy.findUnique({ where: { tenantId: tenant.id } }),
    clientAiSpend(tenant.id),
    db.aiProvider.findMany({ where: { enabled: true, OR: [{ tenantId: null }, { tenantId: tenant.id }] }, orderBy: [{ tenantId: "desc" }, { name: "asc" }] }),
    db.user.findUnique({ where: { id: user.id }, select: { preferences: true } }),
  ]);

  const canEdit = can(user, "rulebook.edit");
  const canSign = can(user, "rulebook.sign");
  const active = state.active ? parseStored(state.active) : null;
  const draft = state.draft ? parseStored(state.draft) : null;
  const template = templateFor(industryFromText(tenant.industry));
  const editing = draft ?? active ?? buildTemplate(template);
  const now = new Date();
  const rules = active?.dataHandling ?? null;
  const rulesText = rules
    ? `${AI_RESIDENCY[rules.residency]}${rules.residency === "region" ? ` (${rules.regions.join(", ") || "no region named"})` : ""}; ${rules.allowedProviders.length ? `${rules.allowedProviders.length} allowed provider${rules.allowedProviders.length === 1 ? "" : "s"} plus the client's own` : "any provider HELIOS offers"}; personal data ${rules.redactPii ? "masked for cloud models" : "not masked"}; users ${rules.allowUserChoice ? "may" : "may not"} choose their own model.`
    : "No rulebook in force: any provider HELIOS offers, without masking.";
  const prefs = me?.preferences && typeof me.preferences === "object" ? ((me.preferences as { aiModels?: Record<string, string> }).aiModels ?? {}) : {};
  const versions = state.versions.map((v, i) => {
    const previous = state.versions.slice(i + 1).find((p) => p.status === "ACTIVE" || p.status === "SUPERSEDED");
    return { ...v, diff: diffRulebooks(previous ? parseStored(previous) : null, parseStored(v)) };
  });

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2 text-base">
            <ShieldCheck className="size-4" /> {user.isClient ? "Your rulebook" : `${tenant.name} · rulebook`} {tenant.isTest && <TestBadge />}
            {!user.isClient && <Link href="/rulebook" className="ml-auto text-xs font-normal text-muted-foreground hover:underline" scroll={false} prefetch={false}>All clients</Link>}
          </CardTitle>
          <CardDescription>
            What HELIOS may do on {user.isClient ? "your" : "this client's"} estate. On every decision the order is fixed and the most restrictive rule wins: kill switch, plan ({tenant.plan ? AUTONOMY_LABEL[tenant.plan.defaultAutonomyCap].toLowerCase() : "no plan"}), AI consent ({AUTONOMY_LABEL[tenant.aiAutonomyCap].toLowerCase()}), this rulebook, the agent profile, then rate limits.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            {state.active ? (
              <>
                <Badge variant="success">v{state.active.version} in force</Badge>
                <span className="text-xs text-muted-foreground">
                  Signed by {state.active.signedByName} {state.active.signedAt && formatRelative(state.active.signedAt, now)} · fingerprint <code className="font-mono">{state.active.contentHash.slice(0, 12)}</code>
                </span>
              </>
            ) : (
              <span className="text-sm text-muted-foreground">No rulebook in force yet: only the plan, AI consent and agent profiles apply. Start from the template below.</span>
            )}
            {state.draft && <Badge variant={STATUS_VARIANT[state.draft.status]}>v{state.draft.version} {STATUS_LABEL[state.draft.status].toLowerCase()}</Badge>}
          </div>
          {(reminders.reviewOverdue || reminders.expiring.length > 0) && (
            <div className="flex flex-col gap-1 rounded-md border border-warning/50 bg-warning/5 p-2 text-xs">
              {reminders.reviewOverdue && <p className="flex items-center gap-1.5"><AlertTriangle className="size-3.5 text-warning" /> Review overdue since {reminders.reviewDue?.toISOString().slice(0, 10)}: confirm the rules still fit, then sign a new version.</p>}
              {reminders.expiring.map((e) => <p key={e.id} className="flex items-center gap-1.5"><AlertTriangle className="size-3.5 text-warning" /> Allowlist entry {e.value} ({e.reason}) expires {e.expiresAt?.toISOString().slice(0, 10)}.</p>)}
            </div>
          )}
          {state.draft && (
            <div className="flex flex-col gap-2">
              {state.draft.reason && <p className="text-xs text-muted-foreground">Draft v{state.draft.version} by {state.draft.authoredByName}: {state.draft.reason}</p>}
              <DraftControls tenantId={tenant.id} status={state.draft.status as "DRAFT" | "AWAITING_SIGNATURE"} version={state.draft.version} canEdit={canEdit} />
              {canSign && (state.draft.status === "AWAITING_SIGNATURE" || !user.isClient) && <SignPanel tenantId={tenant.id} version={state.draft.version} isClient={user.isClient} />}
              {user.isClient && state.draft.status === "DRAFT" && <p className="text-xs text-muted-foreground">Your SOC is still drafting this version; you&apos;ll be asked to sign it.</p>}
            </div>
          )}
        </CardContent>
      </Card>

      <Tabs defaultValue={active ? "rules" : "edit"} className="gap-4">
        <TabsList className="flex-wrap">
          <TabsTrigger value="rules">In force</TabsTrigger>
          <TabsTrigger value="edit">{draft ? `Draft v${state.draft!.version}` : canEdit ? "Edit" : "Template"}</TabsTrigger>
          <TabsTrigger value="dry">Dry run</TabsTrigger>
          <TabsTrigger value="allow">Allowlist ({allowlist.length})</TabsTrigger>
          <TabsTrigger value="versions">Versions ({state.versions.length})</TabsTrigger>
          <TabsTrigger value="ai">AI models</TabsTrigger>
          <TabsTrigger value="code">Policy as code</TabsTrigger>
        </TabsList>
        <TabsContent value="rules">
          {active ? <RulebookSummary book={active} /> : <p className="text-sm text-muted-foreground">Nothing in force yet.</p>}
        </TabsContent>
        <TabsContent value="edit">
          {draft || canEdit ? (
            <RulebookEditor
              key={state.draft?.updatedAt.toISOString() ?? "new"}
              tenantId={tenant.id}
              initial={editing}
              active={active}
              template={(state.draft?.template as typeof template | null) ?? template}
              timeZone={editing.schedule.timeZone}
              inventory={endpoints.map((e) => {
                const group = endpointClass(e);
                return { hostname: e.hostname, group, type: assetTypeLabel(group, e.assetType), criticality: e.criticality };
              })}
              accounts={accounts.map((a) => a.userName!).filter(Boolean)}
              providers={providers}
              canEdit={canEdit}
            />
          ) : (
            <RulebookSummary book={buildTemplate(template)} />
          )}
        </TabsContent>
        <TabsContent value="dry">
          <DryRunPanel tenantId={tenant.id} book={draft ?? active ?? EMPTY_RULEBOOK} label={draft ? `draft v${state.draft!.version}` : active ? `v${state.active!.version}` : "the default rules"} />
        </TabsContent>
        <TabsContent value="allow">
          <AllowlistPanel
            tenantId={tenant.id}
            canEdit={canEdit}
            rows={allowlist.map((r) => ({ id: r.id, kind: r.kind, value: r.value, reason: r.reason, owner: r.owner, expiresAt: r.expiresAt?.toISOString() ?? null, expired: !!r.expiresAt && r.expiresAt <= now }))}
          />
        </TabsContent>
        <TabsContent value="versions">
          {versions.length === 0 ? (
            <p className="text-sm text-muted-foreground">No versions yet.</p>
          ) : (
            <ul className="flex flex-col gap-2">
              {versions.map((v) => (
                <li key={v.id} className="rounded-lg border p-3 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">v{v.version}</span>
                    <Badge variant={STATUS_VARIANT[v.status]}>{STATUS_LABEL[v.status]}</Badge>
                    <span className="text-xs text-muted-foreground">
                      by {v.authoredByName} {formatRelative(v.updatedAt, now)}
                      {v.signedByName && ` · signed by ${v.signedByName}${v.signedAt ? ` ${formatRelative(v.signedAt, now)}` : ""}`} · <code className="font-mono">{v.contentHash.slice(0, 12)}</code>
                    </span>
                  </div>
                  {v.reason && <p className="mt-1 text-xs">{v.reason}</p>}
                  {v.signatureNote && <p className="mt-1 text-xs text-muted-foreground">{v.signatureNote}</p>}
                  <details className="mt-1">
                    <summary className="cursor-pointer text-xs text-muted-foreground">{v.diff.length} change{v.diff.length === 1 ? "" : "s"} from the version before</summary>
                    <ul className="mt-1 font-mono text-[11px]">
                      {v.diff.map((c, i) => (
                        <li key={i} className={c.kind === "removed" ? "text-destructive" : c.kind === "added" ? "text-success" : ""}>
                          {c.kind === "changed" ? `~ ${c.path}: ${c.before} → ${c.after}` : `${c.kind === "added" ? "+" : "−"} ${c.path}: ${c.after ?? c.before}`}
                        </li>
                      ))}
                    </ul>
                  </details>
                </li>
              ))}
            </ul>
          )}
        </TabsContent>
        <TabsContent value="ai">
          <ClientAiPanel
            tenantId={tenant.id}
            canEdit={user.isClient ? canEdit : can(user, "ai.configure")}
            rulesText={rulesText}
            agents={aiPreview.map((a) => ({ key: a.key, name: AGENT_TYPES[a.key].name, resolution: a.resolution }))}
            providers={aiProviders.map((p) => ({
              id: p.id,
              name: p.name,
              kind: p.kind,
              model: p.model,
              isLocal: p.isLocal,
              region: p.region,
              own: p.tenantId === tenant.id,
              lastCheckOk: p.lastCheckOk,
              lastCheckMessage: p.lastCheckMessage,
              blocked: whyNot({ source: "client", id: p.id, name: p.name, model: p.model, isLocal: p.isLocal, region: p.region, tenantId: p.tenantId }, tenant.id, rules),
            }))}
            defaults={(aiPolicy?.defaults as Record<string, string> | null) ?? {}}
            budget={aiPolicy?.monthlyBudgetUsd ?? null}
            spend={aiSpend}
            mine={rules?.allowUserChoice && can(user, "ai.dispatch") ? prefs : null}
          />
        </TabsContent>
        <TabsContent value="code">
          <CodePanel tenantId={tenant.id} book={draft ?? active ?? editing} canEdit={canEdit} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
