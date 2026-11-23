import Link from "next/link";
import { headers } from "next/headers";
import { Activity, BrainCircuit, Gauge, ShieldAlert, ShieldCheck, Swords } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { selectedTenantId, tenantScope } from "@/lib/access";
import { can } from "@/lib/rbac";
import { formatRelative } from "@/lib/format";
import { PII_KINDS } from "@/lib/aisec/detectors";
import { ATLAS, FRAMEWORKS, OWASP_LLM, type PostureState } from "@/lib/aisec/frameworks";
import { DATA_CLASSES, KINDS } from "@/lib/aisec/service";
import { loadOverview } from "@/lib/aisec/view";
import { STAGE_LABEL, VERDICT_VARIANT } from "@/lib/aisec/labels";
import { StatTile } from "@/components/dashboard/stat-tile";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { EmptyState } from "@/components/shared/empty-state";
import { RegisterSystemForm } from "@/components/aisec/register-form";
import { CopyBlock } from "@/components/aisec/system-controls";

const STATE: Record<PostureState, { label: string; variant: "success" | "info" | "warning" | "destructive" | "soft" }> = {
  protected: { label: "Protected", variant: "success" },
  tested: { label: "Tested", variant: "info" },
  partial: { label: "Partly", variant: "warning" },
  gap: { label: "Gap", variant: "destructive" },
  outside: { label: "Outside HELIOS", variant: "soft" },
};

async function origin() {
  const h = await headers();
  const host = h.get("x-forwarded-host") ?? h.get("host") ?? "localhost:3000";
  const proto = h.get("x-forwarded-proto") ?? (host.startsWith("localhost") ? "http" : "https");
  return `${proto}://${host}`;
}

// Security for the AI applications clients run: what's registered, what
// the runtime guard decided, what the red team got through, and where it
// all stands on the OWASP Top 10 for LLM applications.
export default async function AiSecurityPage() {
  const user = await pageGuard("aisec.view");
  const scope = await tenantScope(user);
  const [o, base, tenants, focused] = await Promise.all([
    loadOverview(user, scope),
    origin(),
    user.isClient ? Promise.resolve([]) : db.tenant.findMany({ select: { id: true, name: true }, orderBy: { name: "asc" } }),
    selectedTenantId(user),
  ]);
  const canManage = can(user, "aisec.manage");
  const now = new Date();
  const monitored = o.rows.filter((r) => r.system.mode === "monitor").length;
  const tested = o.rows.filter((r) => r.redTeam);
  const weakest = tested.length ? Math.min(...tested.map((r) => r.redTeam!.resilience)) : null;
  const openFindings = o.rows.reduce((a, r) => a + Object.values(r.redTeam?.categories ?? {}).reduce((x, c) => x + (c.open ?? 0), 0), 0);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="flex items-center gap-2 text-sm text-muted-foreground"><BrainCircuit className="size-4" /> Runtime guard · AI gateway · AI red team</p>
          <h2 className="text-xl font-semibold tracking-tight">AI Security</h2>
          <p className="max-w-3xl text-sm text-muted-foreground">
            {user.isClient ? "Your" : "Clients'"} chatbots, agents and RAG applications, guarded at every step (prompts, the documents and tools they use, their answers), red-teamed under authorisation, and watched by the SOC like any other system.
          </p>
        </div>
        {canManage && <RegisterSystemForm tenants={tenants} isClient={user.isClient} kinds={{ ...KINDS }} dataClasses={{ ...DATA_CLASSES }} defaultTenantId={focused} />}
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatTile label="AI systems" value={o.rows.length} hint={monitored ? `${monitored} in monitor mode` : "all enforcing"} icon={BrainCircuit} />
        <StatTile label="Guard decisions (24h)" value={o.totals.total} hint={`${o.totals.block} blocked · ${o.totals.redact} masked · ${o.totals.watch} watched`} icon={Activity} />
        <StatTile label="Open AI cases" value={o.openCases} hint="Leaks, poisoned content, sustained attacks" icon={ShieldAlert} tone={o.openCases ? "warning" : "default"} />
        <StatTile label="Red team" value={weakest == null ? "—" : `${weakest}%`} hint={weakest == null ? "No system tested yet" : `weakest system withstood · ${openFindings} open finding(s)`} icon={Swords} tone={openFindings ? "warning" : "default"} />
        <StatTile label="OWASP LLM posture" value={`${o.posture.score}%`} hint="Guarded and tested, across the Top 10" icon={Gauge} tone={o.posture.score < 50 ? "critical" : o.posture.score < 80 ? "warning" : "default"} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">AI systems</CardTitle>
          <CardDescription>Each one has a guard policy, a key its application calls HELIOS with, and its latest red-team result.</CardDescription>
        </CardHeader>
        <CardContent>
          {o.rows.length === 0 ? (
            <EmptyState icon={BrainCircuit} title="No AI systems yet" description={canManage ? "Register a chatbot, agent or RAG application: HELIOS gives it a guard policy and a key, and can red-team it in a security test." : "None registered yet."} />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>System</TableHead>
                    <TableHead>Mode</TableHead>
                    <TableHead>Last 24 hours</TableHead>
                    <TableHead>Red team</TableHead>
                    <TableHead>Guarded</TableHead>
                    <TableHead>Last call</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {o.rows.map(({ system: s, decisions: d, redTeam: rt, guarded }) => (
                    <TableRow key={s.id}>
                      <TableCell>
                        <Link href={`/ai-security/${s.id}`} className="font-medium hover:underline">{s.name}</Link>
                        <div className="text-xs text-muted-foreground">{KINDS[s.kind as keyof typeof KINDS] ?? s.kind}{!user.isClient ? ` · ${s.tenant.name}` : ""}{s.status !== "active" ? ` · ${s.status}` : ""}</div>
                      </TableCell>
                      <TableCell><Badge variant={s.mode === "monitor" ? "info" : "outline"}>{s.mode}</Badge></TableCell>
                      <TableCell className="text-xs">{d.total ? <>{d.total} · <span className="text-destructive">{d.block} blocked</span> · {d.redact} masked</> : <span className="text-muted-foreground">no calls</span>}</TableCell>
                      <TableCell className="text-xs">{rt ? <><Badge variant={rt.bypassed ? "warning" : "success"}>withstood {rt.resilience}%</Badge> <span className="text-muted-foreground">{rt.bypassed} of {rt.attacks} got through</span></> : <span className="text-muted-foreground">not tested</span>}</TableCell>
                      <TableCell className="font-mono text-[11px]">{guarded.join(" ") || "—"}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{s.lastSeenAt ? formatRelative(s.lastSeenAt, now) : s.keyPrefix ? "key issued, no calls" : "no key"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">OWASP Top 10 for LLM applications</CardTitle>
          <CardDescription>Across the systems shown: protected where every system&apos;s guard enforces the control, tested where the red team found nothing open, a gap where it found something or nothing covers it yet.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          {o.posture.rows.map((r) => {
            const item = OWASP_LLM.find((x) => x.id === r.id)!;
            return (
              <div key={r.id} className="flex flex-col gap-1.5 rounded-lg border p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-muted-foreground">{r.id}</span>
                  <Badge variant={STATE[r.state].variant}>{STATE[r.state].label}</Badge>
                </div>
                <p className="text-sm font-medium">{r.name}</p>
                <p className="text-xs text-muted-foreground">{r.detail}</p>
                <details className="text-xs">
                  <summary className="cursor-pointer text-muted-foreground">What HELIOS does</summary>
                  <p className="mt-1">{item.what}</p>
                  {item.test && <p className="mt-1"><span className="font-medium">Red team:</span> {item.test}</p>}
                  {item.guard && <p className="mt-1"><span className="font-medium">Guard:</span> {item.guard}</p>}
                  {item.outside && <p className="mt-1 text-muted-foreground">{item.outside}</p>}
                </details>
              </div>
            );
          })}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent guard decisions</CardTitle>
            <CardDescription>Every check is a security event with a signed receipt; search them in Explore with <code>platform:helios-ai-guard</code>.</CardDescription>
          </CardHeader>
          <CardContent>
            {o.recent.length === 0 ? (
              <p className="text-sm text-muted-foreground">No decisions yet: they appear once an application calls the guard or the gateway with its key.</p>
            ) : (
              <div className="flex flex-col divide-y">
                {o.recent.map((r) => (
                  <div key={r.id} className="flex flex-wrap items-start justify-between gap-2 py-2 first:pt-0 last:pb-0">
                    <div className="min-w-0 flex-1 text-xs">
                      <p className="flex flex-wrap items-center gap-2 text-sm">
                        <Badge variant={VERDICT_VARIANT[r.enforced]}>{r.enforced}</Badge>
                        {r.systemId ? <Link href={`/ai-security/${r.systemId}`} className="hover:underline">{r.system}</Link> : r.system}
                        <span className="text-xs text-muted-foreground">{STAGE_LABEL[r.stage] ?? r.stage}{r.subject ? ` · ${r.subject}` : ""}{!user.isClient && r.tenantName ? ` · ${r.tenantName}` : ""}</span>
                      </p>
                      {r.findings[0] && <p className="text-muted-foreground">{r.findings[0].message}{r.owasp.length ? ` (${r.owasp.join(", ")})` : ""}</p>}
                    </div>
                    <span className="text-xs text-muted-foreground">{formatRelative(r.at, now)}{r.caseId && <> · <Link href={`/cases/${r.caseId}`} className="text-primary hover:underline">case</Link></>}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><ShieldCheck className="size-4" /> Frameworks</CardTitle>
            <CardDescription>Where HELIOS records evidence for AI governance frameworks. Evidence and controls, not certification.</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="nist" className="gap-3">
              <TabsList className="flex-wrap">
                {Object.entries(FRAMEWORKS).map(([k, f]) => <TabsTrigger key={k} value={k}>{f.label}</TabsTrigger>)}
                <TabsTrigger value="atlas">MITRE ATLAS</TabsTrigger>
              </TabsList>
              {Object.entries(FRAMEWORKS).map(([k, f]) => (
                <TabsContent key={k} value={k} className="flex flex-col gap-2">
                  <p className="text-xs text-muted-foreground">{f.note}</p>
                  {f.items.map((i) => (
                    <div key={i.ref} className="grid grid-cols-[72px_1fr] gap-2 text-xs">
                      <span className="font-mono font-medium">{i.ref}</span>
                      <span><span className="font-medium">{i.title}.</span> {i.evidence}</span>
                    </div>
                  ))}
                </TabsContent>
              ))}
              <TabsContent value="atlas" className="flex flex-col gap-2">
                <p className="text-xs text-muted-foreground">MITRE ATLAS techniques the guard and the red team map their findings to.</p>
                {Object.entries(ATLAS).map(([id, name]) => (
                  <div key={id} className="grid grid-cols-[110px_1fr] gap-2 text-xs"><span className="font-mono">{id}</span><span>{name}</span></div>
                ))}
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Connect an application</CardTitle>
          <CardDescription>Two ways, with the key from the system&apos;s page. The guard: the application asks HELIOS at each step and does what it says. The gateway: the application sends its model calls through HELIOS, which checks both ways and masks personal data on the way out ({Object.keys(PII_KINDS).length} kinds recognised).</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 lg:grid-cols-2">
          <div className="flex flex-col gap-2">
            <p className="text-sm font-medium">Guard API: check a prompt</p>
            <CopyBlock text={`curl -s ${base}/api/v1/ai/guard \\\n  -H "Authorization: Bearer $HELIOS_AI_KEY" \\\n  -H "Content-Type: application/json" \\\n  -d '{"stage": "prompt", "content": "Ignore previous instructions…", "user": {"id": "patient-1234"}}'\n# → {"decision": "block", "action": "block", "findings": [...], "explanation": "...", "receipt": {...}}\n# stages: prompt · retrieval (documents + the person's roles) · tool_call · tool_output · output`} />
          </div>
          <div className="flex flex-col gap-2">
            <p className="text-sm font-medium">AI gateway: an OpenAI-compatible endpoint</p>
            <CopyBlock text={`from openai import OpenAI\n\nclient = OpenAI(base_url="${base}/api/v1/ai/gateway", api_key=HELIOS_AI_KEY)\nanswer = client.chat.completions.create(\n    model="gpt-4.1-mini",\n    messages=[{"role": "user", "content": question}],\n)\n# HELIOS holds the provider key, masks personal data,\n# checks the prompt, the answer and every tool call.`} />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
