import { ConnectorError, cachedToken } from "@/lib/connectors/http";
import type { ConnectorCtx } from "@/lib/connectors/types";
import { HOUR, MINUTE, type Collector } from "@/lib/collectors/types";
import { asList, pollSince, readCursor, sameHost } from "@/lib/collectors/paging";

const DAY = 24 * HOUR;
const trim = (url: string | undefined) => url?.replace(/\/+$/, "");

// ---------------------------------------------------------------- Okta System Log

// Polling: sortOrder=ASCENDING with no `until`. Okta always returns a next
// link (Link: <…>; rel="next"), even when nothing new has arrived; that
// link (its `after` cursor) is the checkpoint. A full page means more now.
const OKTA_LIMIT = 1000;

export function nextLink(header: string | null): string | undefined {
  for (const part of (header ?? "").split(",")) {
    const m = part.match(/<([^>]+)>\s*;\s*rel="?next"?/);
    if (m) return m[1];
  }
  return undefined;
}

export const oktaCollector: Collector = {
  key: "okta_logs",
  label: "Okta System Log",
  tools: ["okta_workforce"],
  fields: [
    { key: "orgUrl", label: "Okta org URL", required: true, placeholder: "https://acme.okta.com" },
    { key: "apiToken", label: "API token", secret: true, required: true, hint: "A read-only administrator's token is enough for the System Log" },
  ],
  docs: "Okta Management API: System Log, GET /api/v1/logs (polling requests)",
  streams: [
    {
      key: "okta.logs",
      label: "System Log",
      format: "okta",
      permissions: "Read-only administrator (okta.logs.read)",
      everyMs: MINUTE,
      initialLookbackMs: DAY,
      async poll(ctx, cursor, { now, test }) {
        const org = trim(ctx.config.orgUrl);
        if (!org) throw new ConnectorError("Set the Okta org URL", null);
        if (!ctx.secrets.apiToken) throw new ConnectorError("Set the API token", null);
        const limit = test ? 5 : OKTA_LIMIT;
        const url = cursor && !test ? sameHost(cursor, org) : `${org}/api/v1/logs?since=${encodeURIComponent(new Date(now.getTime() - (test ? HOUR : DAY)).toISOString())}&sortOrder=ASCENDING&limit=${limit}`;
        const res = await ctx.http<unknown[]>(url, { headers: { authorization: `SSWS ${ctx.secrets.apiToken}` } });
        const records = asList(res.data);
        const next = nextLink(res.headers.get("link"));
        return { records, cursor: test ? cursor : (next ? sameHost(next, org) : cursor), more: !test && records.length >= limit };
      },
    },
  ],
};

// ---------------------------------------------------------------- CrowdStrike Falcon alerts

// GET /alerts/queries/alerts/v2 (FQL filter, sort field|asc) returns
// composite ids; POST /alerts/entities/alerts/v2 { composite_ids } the alerts.
const FALCON_LIMIT = 500;

async function falconAuth(ctx: ConnectorCtx, base: string) {
  const { clientId } = ctx.config;
  const { clientSecret } = ctx.secrets;
  if (!clientId || !clientSecret) throw new ConnectorError("Set the API client ID and secret", null);
  const token = await cachedToken(`${ctx.cacheKey}:falcon`, async () => {
    const res = await ctx.http<{ access_token: string; expires_in: number }>(`${base}/oauth2/token`, { form: { client_id: clientId, client_secret: clientSecret } });
    return { token: res.data.access_token, expiresIn: Number(res.data.expires_in) || 1800 };
  });
  return { authorization: `Bearer ${token}` };
}

export const crowdstrikeCollector: Collector = {
  key: "falcon_alerts",
  label: "CrowdStrike Falcon alerts",
  tools: ["crowdstrike_falcon_enterprise", "crowdstrike_falcon_pro"],
  fields: [
    { key: "baseUrl", label: "API base URL", placeholder: "https://api.crowdstrike.com", hint: "US-2: https://api.us-2.crowdstrike.com · EU-1: https://api.eu-1.crowdstrike.com" },
    { key: "clientId", label: "API client ID", required: true },
    { key: "clientSecret", label: "API client secret", secret: true, required: true },
  ],
  docs: "Falcon API: GET /alerts/queries/alerts/v2, POST /alerts/entities/alerts/v2",
  streams: [
    {
      key: "falcon.alerts",
      label: "Alerts",
      format: "crowdstrike",
      permissions: "API client scope Alerts: Read",
      everyMs: MINUTE,
      initialLookbackMs: DAY,
      async poll(ctx, cursor, { now, test }) {
        const base = trim(ctx.config.baseUrl) || "https://api.crowdstrike.com";
        const c = readCursor(cursor, now, test ? HOUR : DAY);
        const headers = await falconAuth(ctx, base);
        const limit = test ? 5 : FALCON_LIMIT;
        // >= and not >: alerts that share the last timestamp aren't skipped; their repeats are dropped as known.
        const filter = encodeURIComponent(`updated_timestamp:>='${c.since}'`);
        const ids = asList((await ctx.http<{ resources?: string[] }>(`${base}/alerts/queries/alerts/v2?filter=${filter}&sort=${encodeURIComponent("updated_timestamp|asc")}&limit=${limit}`, { headers })).data.resources);
        if (!ids.length) return { records: [], cursor: JSON.stringify(c), more: false };
        const alerts = asList((await ctx.http<{ resources?: unknown[] }>(`${base}/alerts/entities/alerts/v2`, { headers, json: { composite_ids: ids } })).data.resources);
        const newest = alerts.map((a) => (a as Record<string, string>).updated_timestamp).filter(Boolean).sort().pop();
        // A full page all at one timestamp would loop: step past it.
        const since = newest && newest !== c.since ? newest : new Date(Date.parse(c.since) + 1).toISOString();
        return { records: alerts, cursor: test ? cursor : JSON.stringify({ since }), more: !test && ids.length >= limit };
      },
    },
  ],
};

// ---------------------------------------------------------------- SentinelOne threats

export const sentineloneCollector: Collector = {
  key: "s1_threats",
  label: "SentinelOne threats",
  tools: ["sentinelone_complete", "sentinelone_core"],
  fields: [
    { key: "consoleUrl", label: "Management console URL", required: true, placeholder: "https://usea1-acme.sentinelone.net" },
    { key: "apiToken", label: "API token", secret: true, required: true, hint: "A service user with the Viewer role on the client's site" },
  ],
  docs: "Management API v2.1: GET /web/api/v2.1/threats (createdAt__gte, sortBy, cursor)",
  streams: [
    {
      key: "s1.threats",
      label: "Threats",
      format: "sentinelone",
      permissions: "Service user with Viewer on the site or account",
      everyMs: MINUTE,
      initialLookbackMs: DAY,
      async poll(ctx, cursor, { now, test }) {
        const console = trim(ctx.config.consoleUrl);
        if (!console) throw new ConnectorError("Set the management console URL", null);
        if (!ctx.secrets.apiToken) throw new ConnectorError("Set the API token", null);
        return pollSince(cursor, { now, lookbackMs: test ? HOUR : DAY, overlapMs: 5 * MINUTE }, async ({ since, next }) => {
          const params = new URLSearchParams({ createdAt__gte: since, sortBy: "createdAt", sortOrder: "asc", limit: String(test ? 5 : 200) });
          if (next) params.set("cursor", next);
          const res = await ctx.http<{ data?: unknown[]; pagination?: { nextCursor?: string | null } }>(`${console}/web/api/v2.1/threats?${params}`, { headers: { authorization: `ApiToken ${ctx.secrets.apiToken}` } });
          const records = asList(res.data.data);
          return {
            records,
            next: test ? undefined : (res.data.pagination?.nextCursor ?? undefined),
            times: records.map((r) => {
              const t = r as { threatInfo?: { createdAt?: string }; createdAt?: string };
              return t.threatInfo?.createdAt ?? t.createdAt;
            }),
          };
        });
      },
    },
  ],
};
