"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Check, Copy, HardDrive, Loader2, Plug, Zap } from "lucide-react";
import { toast } from "sonner";
import type { UserRole } from "@prisma/client";

import { onboardIntegrationAction } from "@/app/(app)/integrations/actions";
import { ROLES } from "@/lib/rbac";
import { capabilityName, capabilityShort } from "@/lib/assets/capabilities";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { TenantSelect } from "@/components/shared/tenant-select";

export interface CategoryView {
  key: string;
  label: string;
  description: string;
  defaultRoles: UserRole[];
}

export interface ToolView {
  key: string;
  name: string;
  vendor: string;
  category: string;
  description: string;
  controls: string[];
  actions: string[];
  ingest: boolean;
  offlineCapable: boolean;
  platforms: string[];
}

interface Props {
  categories: CategoryView[];
  tools: ToolView[];
  tenants: Array<{ id: string; name: string }>;
  defaultTenantId: string | null;
  isClient: boolean;
  team: Array<{ id: string; name: string; role: string }>;
  origin: string;
}

const STAFF_ROLES: UserRole[] = ["SOC_MANAGER", "TRIAGE_ANALYST", "ANALYST", "INCIDENT_RESPONDER", "THREAT_HUNTER", "DETECTION_ENGINEER", "AUDITOR"];

export function CopyField({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <div className="grid gap-1">
      {label && <span className="text-xs text-muted-foreground">{label}</span>}
      <div className="flex items-center gap-1 rounded-md border bg-muted/50 px-2 py-1.5">
        <code className="min-w-0 flex-1 truncate font-mono text-xs" title={value}>{value}</code>
        <Button
          size="icon"
          variant="ghost"
          className="size-6"
          aria-label="Copy"
          onClick={() => {
            void navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
        >
          {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
        </Button>
      </div>
    </div>
  );
}

export function OnboardWizard({ categories, tools, tenants, defaultTenantId, isClient, team, origin }: Props) {
  const router = useRouter();
  const [category, setCategory] = React.useState(categories[0]?.key ?? "edr");
  const [toolKey, setToolKey] = React.useState<string | null>(null);
  const [tenantId, setTenantId] = React.useState(defaultTenantId ?? "none");
  const [name, setName] = React.useState("");
  const [roles, setRoles] = React.useState<UserRole[]>([]);
  const [users, setUsers] = React.useState<string[]>([]);
  const [responseUrl, setResponseUrl] = React.useState("");
  const [secret, setSecret] = React.useState("");
  const [chatUrl, setChatUrl] = React.useState("");
  const [result, setResult] = React.useState<{ id: string; token: string | null; ingestPath: string } | null>(null);

  const tool = tools.find((t) => t.key === toolKey);
  const cat = categories.find((c) => c.key === category);

  function pickTool(key: string) {
    setToolKey(key);
    setRoles(cat?.defaultRoles ?? []);
    setResult(null);
  }

  const onboard = useMutation({
    mutationFn: () =>
      onboardIntegrationAction({
        vendor: toolKey!,
        tenantId,
        name,
        allowedRoles: roles,
        assignedUserIds: users,
        responseWebhookUrl: responseUrl,
        webhookSecret: secret,
        chatWebhookUrl: chatUrl,
      }),
    onSuccess: (r) => {
      setResult(r);
      toast.success("Tool onboarded");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Onboarding failed"),
  });

  if (result && tool) {
    const url = `${origin}${result.ingestPath}`;
    return (
      <div className="flex flex-col gap-4">
        <div className="flex items-start gap-3 rounded-lg border border-success/40 bg-success/5 p-4">
          <Check className="mt-0.5 size-5 text-success-ink" />
          <div>
            <p className="text-sm font-semibold">{tool.vendor} {tool.name} is onboarded</p>
            <p className="text-xs text-muted-foreground">
              {result.token ? "Point the tool's alert/event export (webhook, SIEM forwarder, Logic App, Lambda…) at the ingest URL. The token is shown once — store it in the tool now." : "This tool doesn't push data; it's used for notifications or tickets."}
            </p>
          </div>
        </div>
        {result.token && (
          <div className="grid gap-3">
            <CopyField label="Ingest URL" value={url} />
            <CopyField label="Bearer token (shown once)" value={result.token} />
            <CopyField label="Try it" value={`curl -X POST ${url} -H "Authorization: Bearer ${result.token}" -H "content-type: application/json" -d '{"title":"Test alert","severity":"high","host":"TEST-HOST","user":"test.user"}'`} />
          </div>
        )}
        <div>
          <Button variant="outline" onClick={() => { setResult(null); setToolKey(null); setName(""); }}>Onboard another tool</Button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-1.5">
        {categories.map((c) => (
          <button
            key={c.key}
            type="button"
            onClick={() => { setCategory(c.key); setToolKey(null); }}
            className={cn("rounded-full border px-3 py-1 text-xs font-medium transition-colors hover:bg-accent", category === c.key && "border-primary bg-primary text-primary-foreground hover:bg-primary/90")}
          >
            {c.label}
          </button>
        ))}
      </div>
      {cat && <p className="text-xs text-muted-foreground">{cat.description}</p>}
      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
        {tools.filter((t) => t.category === category).map((t) => (
          <button
            key={t.key}
            type="button"
            onClick={() => pickTool(t.key)}
            className={cn("flex flex-col gap-1.5 rounded-lg border p-3 text-left transition-colors hover:border-primary/50 hover:bg-accent/40", toolKey === t.key && "border-primary bg-primary/5 ring-1 ring-primary")}
          >
            <div className="flex items-start justify-between gap-2">
              <div>
                <p className="text-xs text-muted-foreground">{t.vendor}</p>
                <p className="text-sm font-semibold leading-tight">{t.name}</p>
              </div>
              {t.offlineCapable && <Badge variant="info" title="Works on-prem / offline"><HardDrive /> offline</Badge>}
            </div>
            <p className="line-clamp-2 text-xs text-muted-foreground">{t.description}</p>
            <div className="flex flex-wrap gap-1">
              {t.ingest && <Badge variant="soft"><Plug /> alerts</Badge>}
              {t.actions.length > 0 && <Badge variant="soft"><Zap /> {t.actions.length} response action{t.actions.length === 1 ? "" : "s"}</Badge>}
              {t.controls.slice(0, 4).map((c) => (
                <Badge key={c} variant="outline" className="font-mono text-[10px] uppercase" title={capabilityName(c)}>{capabilityShort(c)}</Badge>
              ))}
            </div>
          </button>
        ))}
      </div>

      {tool && (
        <div className="grid gap-4 rounded-lg border bg-muted/20 p-4">
          <div className="grid gap-3 sm:grid-cols-2">
            {!isClient && (
              <div className="grid gap-1.5">
                <Label>Client</Label>
                <TenantSelect tenants={tenants} value={tenantId} onChange={setTenantId} />
              </div>
            )}
            <div className="grid gap-1.5">
              <Label>Display name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={`${tool.vendor} ${tool.name}`} />
            </div>
          </div>

          {!isClient && (
            <div className="grid gap-1.5">
              <Label>Roles that can use this tool</Label>
              <div className="flex flex-wrap gap-1.5">
                {STAFF_ROLES.map((r) => {
                  const on = roles.includes(r);
                  return (
                    <button
                      key={r}
                      type="button"
                      onClick={() => setRoles(on ? roles.filter((x) => x !== r) : [...roles, r])}
                      className={cn("rounded-full border px-2.5 py-0.5 text-xs transition-colors hover:bg-accent", on && "border-primary bg-primary/15 text-primary")}
                    >
                      {ROLES[r].label}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
          {!isClient && team.length > 0 && (
            <div className="grid gap-1.5">
              <Label>Also give access to specific people</Label>
              <div className="flex max-h-28 flex-wrap gap-1.5 overflow-y-auto">
                {team.map((m) => {
                  const on = users.includes(m.id);
                  return (
                    <button
                      key={m.id}
                      type="button"
                      onClick={() => setUsers(on ? users.filter((x) => x !== m.id) : [...users, m.id])}
                      className={cn("rounded-full border px-2.5 py-0.5 text-xs transition-colors hover:bg-accent", on && "border-primary bg-primary/15 text-primary")}
                    >
                      {m.name}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {tool.actions.length > 0 && tool.category !== "chatops" && (
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="grid gap-1.5">
                <Label>Response connector URL (optional)</Label>
                <Input value={responseUrl} onChange={(e) => setResponseUrl(e.target.value)} type="url" aria-describedby="response-url-hint" />
                <p id="response-url-hint" className="text-[11px] text-muted-foreground">HTTPS endpoint of your automation (n8n, Tines, a SOAR or a script) that carries out actions on this tool.</p>
                <p className="text-[11px] text-muted-foreground">Receives signed JSON for: {tool.actions.map((a) => a.toLowerCase().replaceAll("_", " ")).join(", ")}.</p>
              </div>
              <div className="grid gap-1.5">
                <Label>Signing secret</Label>
                <Input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="HMAC-SHA256 key (X-Helios-Signature)" autoComplete="off" />
              </div>
            </div>
          )}
          {tool.category === "chatops" && (
            <div className="grid gap-1.5">
              <Label>Incoming webhook URL</Label>
              <Input type="password" value={chatUrl} onChange={(e) => setChatUrl(e.target.value)} autoComplete="off" aria-describedby="chat-url-hint" />
              <p id="chat-url-hint" className="text-[11px] text-muted-foreground">The incoming-webhook URL from Slack or a Teams workflow.</p>
            </div>
          )}

          <div className="flex items-center gap-2">
            <Button onClick={() => onboard.mutate()} disabled={onboard.isPending || (tool.category === "chatops" && !chatUrl)}>
              {onboard.isPending ? <Loader2 className="animate-spin" /> : <Plug />}
              Onboard {tool.name}
            </Button>
            <span className="text-xs text-muted-foreground">Credentials are encrypted at rest; the ingest token is stored only as a hash.</span>
          </div>
        </div>
      )}
    </div>
  );
}
