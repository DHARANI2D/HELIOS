import Link from "next/link";
import { Bot, CircleDollarSign, Gauge, ShieldBan, ShieldCheck, ThumbsUp } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { aiSettings } from "@/lib/settings";
import { caseVisibility } from "@/lib/access";
import { AGENT_KEYS, AGENT_TYPES } from "@/lib/ai/catalog";
import { aiCostOf } from "@/lib/pricing/service";
import { envClaudeAvailable, loadProfile, resolveProvider } from "@/lib/ai/resolve";
import { PROPOSABLE_ACTIONS } from "@/lib/ai/triage";
import { ACTION_LABEL } from "@/lib/response/executor";
import { formatRelative } from "@/lib/format";
import { StatTile } from "@/components/dashboard/stat-tile";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState } from "@/components/shared/empty-state";
import { SafetyControls } from "@/components/ai/safety-controls";
import { ProvidersPanel } from "@/components/ai/providers-panel";
import { AgentProfileCard } from "@/components/ai/agent-profiles";

async function loadAiPage(visibility: ReturnType<typeof caseVisibility>) {
  const now = new Date();
  const since = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const runScope = { createdAt: { gte: since }, case: visibility };
  // Stack-advisor runs (Build & Price, the public estimator) belong to no case.
  const allRuns = { createdAt: { gte: since }, OR: [{ case: visibility }, { caseId: null, agentKey: "advisor" }] };
  const [settings, providers, runs, recent, feedback, executed, blocked, profilesUsage] = await Promise.all([
    aiSettings(),
    db.aiProvider.findMany({ where: { tenantId: null }, orderBy: [{ isDefault: "desc" }, { createdAt: "asc" }], include: { _count: { select: { agents: true } } } }),
    db.aiRun.findMany({ where: allRuns, select: { model: true, inputTokens: true, outputTokens: true, agentKey: true, status: true } }),
    db.aiRun.findMany({ where: { case: visibility }, orderBy: { createdAt: "desc" }, take: 30, include: { case: { select: { id: true, title: true, tenant: { select: { name: true } } } } } }),
    db.aiRun.groupBy({ by: ["feedback"], where: { ...runScope, feedback: { not: null } }, _count: { _all: true } }),
    db.responseAction.count({ where: { source: "ai", status: "EXECUTED", createdAt: { gte: since }, case: visibility } }),
    db.responseAction.count({ where: { source: "ai", status: "BLOCKED", createdAt: { gte: since }, case: visibility } }),
    db.aiRun.groupBy({ by: ["agentKey"], where: allRuns, _count: { _all: true } }),
  ]);
  const profiles = await Promise.all(
    AGENT_KEYS.map(async (key) => {
      const profile = await loadProfile(key);
      const provider = key === "containment" ? null : await resolveProvider(key, profile);
      return { profile, provider };
    }),
  );
  return { now, settings, providers, runs, recent, feedback, executed, blocked, profilesUsage, profiles };
}

export default async function AiPage() {
  const user = await pageGuard("ai.view");
  const canConfigure = can(user, "ai.configure");
  const { now, settings, providers, runs, recent, feedback, executed, blocked, profilesUsage, profiles } = await loadAiPage(caseVisibility(user));

  const spend = await aiCostOf(runs);
  const agree = feedback.find((f) => f.feedback === "agree")?._count._all ?? 0;
  const disagree = feedback.find((f) => f.feedback === "disagree")?._count._all ?? 0;
  const agreement = agree + disagree ? Math.round((agree / (agree + disagree)) * 100) : null;
  const fallbacks = runs.filter((r) => r.status === "fallback").length;
  const runsByAgent = new Map(profilesUsage.map((p) => [p.agentKey, p._count._all]));
  const providerOptions = providers.filter((p) => p.enabled).map((p) => ({ id: p.id, name: p.name, model: p.model, isLocal: p.isLocal }));

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatTile label="AI runs (30d)" value={runs.length} icon={Bot} />
        <StatTile label="Analyst agreement" value={agreement == null ? "—" : `${agreement}%`} icon={ThumbsUp} />
        <StatTile label="Auto-contained (30d)" value={executed} icon={ShieldCheck} />
        <StatTile label="Blocked by guardrails" value={blocked} icon={ShieldBan} tone={blocked > 0 ? "warning" : "default"} />
        <StatTile label="Model spend (30d, est.)" value={`$${spend.toFixed(2)}`} icon={CircleDollarSign} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Safety controls</CardTitle>
          <CardDescription>
            How far AI may act on its own. Each client&apos;s consent cap (on its Clients page) further limits what happens on their estate; every AI decision is in the audit chain.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SafetyControls {...settings} canConfigure={canConfigure} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Model providers</CardTitle>
          <CardDescription>
            Claude online today; add a local model server (Ollama, LM Studio, vLLM, llama.cpp) for offline or data-residency deployments. With no provider at all,
            every agent runs on HELIOS&apos;s built-in deterministic engine.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ProvidersPanel
            canConfigure={canConfigure}
            envClaude={{ available: envClaudeAvailable(), model: process.env.ANTHROPIC_MODEL ?? "claude-opus-5-5" }}
            providers={providers.map((p) => ({
              id: p.id,
              name: p.name,
              kind: p.kind as "anthropic" | "openai_compatible",
              baseUrl: p.baseUrl,
              model: p.model,
              isLocal: p.isLocal,
              enabled: p.enabled,
              isDefault: p.isDefault,
              hasKey: !!p.apiKeyCipher,
              lastCheckOk: p.lastCheckOk,
              lastCheckMessage: p.lastCheckMessage,
              usedBy: p._count.agents,
            }))}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Agent types</CardTitle>
          <CardDescription>
            Choose which model runs each agent and how much it may do. Analysts dispatch the case-level agents from any case; the triage first responder also runs
            automatically on new cases. The stack advisor suggests tool stacks in Build &amp; Price and on the public estimator.
            {fallbacks > 0 && ` ${fallbacks} run${fallbacks === 1 ? "" : "s"} in the last 30 days fell back to the built-in engine after a model error.`}
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 lg:grid-cols-2">
          {profiles.map(({ profile, provider }) => (
            <AgentProfileCard
              key={profile.key}
              canConfigure={canConfigure}
              providers={providerOptions}
              actions={PROPOSABLE_ACTIONS.map((a) => ({ value: a, label: ACTION_LABEL[a] }))}
              profile={{
                key: profile.key as keyof typeof AGENT_TYPES,
                name: AGENT_TYPES[profile.key as keyof typeof AGENT_TYPES].name,
                description: AGENT_TYPES[profile.key as keyof typeof AGENT_TYPES].description,
                enabled: profile.enabled,
                providerId: profile.providerId,
                model: profile.model,
                autonomy: profile.autonomy,
                effort: profile.effort,
                minConfidence: profile.minConfidence,
                allowedActions: profile.allowedActions,
                instructions: profile.instructions,
                engine: provider ? `${provider.name} · ${provider.model}` : "built-in engine",
                runs30d: runsByAgent.get(profile.key) ?? 0,
              }}
            />
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Gauge className="size-4" /> Run log</CardTitle>
          <CardDescription>Every agent run, the engine that answered, how well its claims were grounded, and what analysts thought of it.</CardDescription>
        </CardHeader>
        <CardContent>
          {recent.length === 0 ? (
            <EmptyState icon={Bot} title="No AI runs yet" description="New cases are triaged automatically; or dispatch an agent from any case." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Case</TableHead>
                    <TableHead>Agent</TableHead>
                    <TableHead>Engine</TableHead>
                    <TableHead>Result</TableHead>
                    <TableHead className="text-right">Confidence</TableHead>
                    <TableHead className="text-right">Tokens</TableHead>
                    <TableHead>Feedback</TableHead>
                    <TableHead className="text-right">When</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {recent.map((r) => {
                    const verdict = (r.output as { verdict?: string } | null)?.verdict;
                    return (
                      <TableRow key={r.id}>
                        <TableCell className="max-w-xs">
                          {r.case ? (
                            <Link href={`/cases/${r.case.id}`} className="line-clamp-1 text-sm font-medium hover:underline">{r.case.title}</Link>
                          ) : (
                            "—"
                          )}
                          {r.case?.tenant && <p className="text-[11px] text-muted-foreground">{r.case.tenant.name}</p>}
                        </TableCell>
                        <TableCell className="text-xs">{AGENT_TYPES[r.agentKey as keyof typeof AGENT_TYPES]?.name ?? r.agentKey}<p className="text-[11px] text-muted-foreground">{r.trigger}</p></TableCell>
                        <TableCell className="text-xs">
                          {r.engine}
                          {r.model && <p className="font-mono text-[11px] text-muted-foreground">{r.model}</p>}
                          {(() => {
                            const why = (r.resolution as { reason?: string; redacted?: boolean } | null) ?? null;
                            return why?.reason ? <p className="line-clamp-2 max-w-56 text-[11px] text-muted-foreground" title={why.reason}>{why.redacted ? "Masked · " : ""}{why.reason}</p> : null;
                          })()}
                        </TableCell>
                        <TableCell>
                          <Badge variant={r.status === "failed" ? "destructive" : r.status === "fallback" ? "warning" : "success"}>{r.status}</Badge>
                          {verdict && <p className="mt-0.5 text-[11px] capitalize text-muted-foreground">{verdict.replace("_", " ")}</p>}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">{r.confidence != null ? `${Math.round(r.confidence * 100)}%` : "—"}</TableCell>
                        <TableCell className="text-right text-xs tabular-nums text-muted-foreground">
                          {r.inputTokens != null ? `${(r.inputTokens / 1000).toFixed(1)}k / ${((r.outputTokens ?? 0) / 1000).toFixed(1)}k` : "—"}
                        </TableCell>
                        <TableCell className="text-xs">{r.feedback ? <Badge variant={r.feedback === "agree" ? "success" : "destructive"}>{r.feedback}</Badge> : "—"}</TableCell>
                        <TableCell className="text-right text-xs text-muted-foreground">{formatRelative(r.createdAt, now)}</TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
