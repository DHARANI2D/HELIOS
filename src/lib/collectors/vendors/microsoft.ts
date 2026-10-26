import { ConnectorError, microsoftToken } from "@/lib/connectors/http";
import type { ConnectorCtx } from "@/lib/connectors/types";
import { HOUR, MINUTE, type Collector, type CollectorStream } from "@/lib/collectors/types";
import { asList, pollSince, sameHost } from "@/lib/collectors/paging";

// Microsoft Graph (Entra ID sign-ins, directory audits and risk detections;
// Defender XDR alerts) and Azure Resource Manager (the Activity Log), with an
// app registration's client credentials. Sign-in logs through the API need
// Entra ID P1 or P2; risk detections need P2.
//   GET /v1.0/auditLogs/signIns?$filter=createdDateTime ge …     AuditLog.Read.All
//   GET /v1.0/auditLogs/directoryAudits?$filter=activityDateTime ge …  AuditLog.Read.All
//   GET /v1.0/identityProtection/riskDetections?$filter=detectedDateTime ge …  IdentityRiskEvent.Read.All
//   GET /v1.0/security/alerts_v2?$filter=lastUpdateDateTime ge …  SecurityAlert.Read.All
//   GET management.azure.com/subscriptions/{id}/providers/Microsoft.Insights/eventtypes/management/values
// Lists are newest first and page with @odata.nextLink (nextLink for ARM).

const GRAPH = "https://graph.microsoft.com";
const DAY = 24 * HOUR;
const ARM = "https://management.azure.com";

const graphHeaders = async (ctx: ConnectorCtx) => ({ authorization: `Bearer ${await microsoftToken(ctx, `${GRAPH}/.default`)}` });

function graphStream(key: string, label: string, path: string, timeField: string, permissions: string, format: CollectorStream["format"], everyMs = 2 * MINUTE): CollectorStream {
  return {
    key,
    label,
    format,
    permissions,
    everyMs,
    initialLookbackMs: DAY,
    async poll(ctx, cursor, { now, test }) {
      return pollSince(cursor, { now, lookbackMs: test ? HOUR : DAY, overlapMs: 15 * MINUTE }, async ({ since, next }) => {
        const url = next ? sameHost(next, GRAPH) : `${GRAPH}/v1.0/${path}?$filter=${encodeURIComponent(`${timeField} ge ${since}`)}&$top=${test ? 5 : 500}`;
        const res = await ctx.http<{ value?: unknown[]; "@odata.nextLink"?: string }>(url, { headers: await graphHeaders(ctx) });
        const records = asList(res.data.value);
        return { records, next: test ? undefined : res.data["@odata.nextLink"], times: records.map((r) => (r as Record<string, string>)[timeField]) };
      });
    },
  };
}

const MS_FIELDS = [
  { key: "tenantId", label: "Directory (tenant) ID", required: true },
  { key: "clientId", label: "Application (client) ID", required: true },
  { key: "clientSecret", label: "Client secret", secret: true, required: true },
];

export const entraCollector: Collector = {
  key: "entra_logs",
  label: "Microsoft Entra ID logs",
  tools: ["entra_p1", "entra_p2"],
  fields: MS_FIELDS,
  docs: "Microsoft Graph v1.0: list signIns, list directoryAudits, list riskDetections",
  streams: [
    graphStream("entra.signins", "Sign-ins", "auditLogs/signIns", "createdDateTime", "AuditLog.Read.All (application); Entra ID P1 or P2", "entra"),
    graphStream("entra.audits", "Directory audits", "auditLogs/directoryAudits", "activityDateTime", "AuditLog.Read.All (application)", "entra"),
    graphStream("entra.risk", "Risk detections", "identityProtection/riskDetections", "detectedDateTime", "IdentityRiskEvent.Read.All (application); Entra ID P2", "entra", 5 * MINUTE),
  ],
};

export const defenderCollector: Collector = {
  key: "defender_alerts",
  label: "Microsoft Defender XDR alerts",
  tools: ["defender_endpoint_p2", "defender_business", "defender_o365_p1", "defender_o365_p2", "defender_identity", "defender_cloud_apps", "defender_cloud"],
  fields: MS_FIELDS,
  docs: "Microsoft Graph v1.0: list alerts_v2 (security API)",
  streams: [graphStream("defender.alerts", "Alerts", "security/alerts_v2", "lastUpdateDateTime", "SecurityAlert.Read.All (application)", "defender")],
};

export const azureCollector: Collector = {
  key: "azure_activity",
  label: "Azure Activity Log",
  tools: ["azure_activity"],
  fields: [...MS_FIELDS, { key: "subscriptionId", label: "Subscription ID", required: true, hint: "One subscription per integration; the app needs the Reader (or Monitoring Reader) role on it" }],
  docs: "Azure Monitor REST: Activity Logs - List (api-version 2015-04-01)",
  streams: [
    {
      key: "azure.activity",
      label: "Activity Log",
      format: "azure_activity",
      permissions: "Monitoring Reader (or Reader) on the subscription",
      everyMs: 5 * MINUTE,
      initialLookbackMs: DAY,
      async poll(ctx, cursor, { now, test }) {
        const sub = ctx.config.subscriptionId;
        if (!sub) throw new ConnectorError("Set the subscription ID", null);
        return pollSince(cursor, { now, lookbackMs: test ? HOUR : DAY, overlapMs: 15 * MINUTE }, async ({ since, next }) => {
          const filter = `eventTimestamp ge '${since}' and eventTimestamp le '${now.toISOString()}'`;
          const url = next ? sameHost(next, ARM) : `${ARM}/subscriptions/${encodeURIComponent(sub)}/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&$filter=${encodeURIComponent(filter)}`;
          const res = await ctx.http<{ value?: unknown[]; nextLink?: string }>(url, { headers: { authorization: `Bearer ${await microsoftToken(ctx, `${ARM}/.default`)}` } });
          const records = asList(res.data.value);
          return { records: test ? records.slice(0, 5) : records, next: test ? undefined : res.data.nextLink, times: records.map((r) => (r as Record<string, string>).eventTimestamp) };
        });
      },
    },
  ],
};
