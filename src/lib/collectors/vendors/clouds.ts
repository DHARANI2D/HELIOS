import { gunzipSync } from "node:zlib";

import { ConnectorError } from "@/lib/connectors/http";
import type { ConnectorCtx } from "@/lib/connectors/types";
import { HOUR, MINUTE, type Collector } from "@/lib/collectors/types";
import { asList, pollSince } from "@/lib/collectors/paging";
import { awsCredentials, awsEncode, googleToken, signAws } from "@/lib/collectors/auth";

const DAY = 24 * HOUR;

// ---------------------------------------------------------------- Google Workspace

// Admin SDK Reports API: GET /admin/reports/v1/activity/users/all/applications/login
// with a service account that has domain-wide delegation for the
// admin.reports.audit.readonly scope, impersonating a Workspace admin.
export const workspaceCollector: Collector = {
  key: "google_workspace",
  label: "Google Workspace login audit",
  tools: ["google_workspace"],
  fields: [
    { key: "adminEmail", label: "Admin to act as", required: true, placeholder: "security-admin@acme.example", hint: "A Workspace admin the service account impersonates (domain-wide delegation)" },
    { key: "serviceAccountKey", label: "Service account JSON key", secret: true, required: true },
  ],
  docs: "Admin SDK Reports API v1: activities.list (applicationName=login)",
  streams: [
    {
      key: "workspace.login",
      label: "Login activity",
      format: "google_workspace",
      permissions: "Domain-wide delegation for https://www.googleapis.com/auth/admin.reports.audit.readonly",
      everyMs: 5 * MINUTE,
      initialLookbackMs: DAY,
      async poll(ctx, cursor, { now, test }) {
        if (!ctx.config.adminEmail) throw new ConnectorError("Set the admin to act as", null);
        const token = await googleToken(ctx, "https://www.googleapis.com/auth/admin.reports.audit.readonly", ctx.config.adminEmail);
        // Reports lag by minutes to hours: reach well back and let the repeats drop.
        return pollSince(cursor, { now, lookbackMs: test ? HOUR : DAY, overlapMs: 2 * HOUR }, async ({ since, next }) => {
          const params = new URLSearchParams({ startTime: since, maxResults: String(test ? 5 : 1000) });
          if (next) params.set("pageToken", next);
          const res = await ctx.http<{ items?: unknown[]; nextPageToken?: string }>(`https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?${params}`, { headers: { authorization: `Bearer ${token}` } });
          const records = asList(res.data.items);
          return { records, next: test ? undefined : res.data.nextPageToken, times: records.map((r) => (r as { id?: { time?: string } }).id?.time) };
        });
      },
    },
  ],
};

// ---------------------------------------------------------------- Google Cloud audit logs (Pub/Sub)

// A log sink routes the audit logs to a Pub/Sub topic; HELIOS pulls its
// subscription and acknowledges what it has queued.
export const gcpCollector: Collector = {
  key: "gcp_audit",
  label: "Google Cloud audit logs",
  tools: ["gcp_audit_logs"],
  fields: [
    { key: "projectId", label: "Project ID", required: true },
    { key: "subscription", label: "Pub/Sub subscription", required: true, placeholder: "helios-audit", hint: "A pull subscription on the topic your log sink writes to" },
    { key: "serviceAccountKey", label: "Service account JSON key", secret: true, required: true },
  ],
  docs: "Pub/Sub REST v1: projects.subscriptions.pull and acknowledge",
  streams: [
    {
      key: "gcp.audit",
      label: "Audit log subscription",
      format: "gcp_audit",
      permissions: "roles/pubsub.subscriber on the subscription",
      everyMs: MINUTE,
      initialLookbackMs: 0,
      async poll(ctx, _cursor, { test }) {
        const { projectId, subscription } = ctx.config;
        if (!projectId || !subscription) throw new ConnectorError("Set the project and subscription", null);
        const token = await googleToken(ctx, "https://www.googleapis.com/auth/pubsub");
        const path = `https://pubsub.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/subscriptions/${encodeURIComponent(subscription)}`;
        const headers = { authorization: `Bearer ${token}` };
        const res = await ctx.http<{ receivedMessages?: Array<{ ackId: string }> }>(`${path}:pull`, { headers, json: { maxMessages: test ? 5 : 500 } });
        const messages = asList(res.data.receivedMessages) as Array<{ ackId: string }>;
        return {
          records: messages,
          cursor: null,
          more: !test && messages.length >= 500,
          // Unacknowledged messages come back after the ack deadline: a test changes nothing.
          commit: test || !messages.length ? undefined : async () => void (await ctx.http(`${path}:acknowledge`, { headers, json: { ackIds: messages.map((m) => m.ackId) } })),
        };
      },
    },
  ],
};

// ---------------------------------------------------------------- AWS CloudTrail (S3 + SQS)

// The trail's bucket sends ObjectCreated notifications to an SQS queue
// (directly or through SNS). HELIOS receives them, reads each new log file
// from S3 (gzipped JSON, { Records: [...] }), and deletes the messages once
// the records are queued. Uses SQS's JSON protocol and SigV4.

interface SqsMessage {
  MessageId: string;
  ReceiptHandle: string;
  Body: string;
}

async function sqs<T>(ctx: ConnectorCtx, region: string, target: string, body: Record<string, unknown>): Promise<T> {
  const url = `https://sqs.${region}.amazonaws.com/`;
  const text = JSON.stringify(body);
  const headers = signAws({ method: "POST", url, region, service: "sqs", body: text, headers: { "content-type": "application/x-amz-json-1.0", "x-amz-target": `AmazonSQS.${target}` }, now: new Date() }, awsCredentials(ctx));
  return (await ctx.http<T>(url, { method: "POST", headers, body: text })).data;
}

// Object keys arrive URL-encoded (spaces as "+").
export function s3Objects(body: string): Array<{ bucket: string; key: string; region?: string }> {
  let msg: Record<string, unknown>;
  try {
    msg = JSON.parse(body);
  } catch {
    return [];
  }
  if (msg.Type === "Notification" && typeof msg.Message === "string") return s3Objects(msg.Message);
  return asList(msg.Records)
    .map((r) => r as { eventName?: string; awsRegion?: string; s3?: { bucket?: { name?: string }; object?: { key?: string } } })
    .filter((r) => r.eventName?.startsWith("ObjectCreated") && r.s3?.bucket?.name && r.s3?.object?.key)
    .map((r) => ({ bucket: r.s3!.bucket!.name!, key: decodeURIComponent(r.s3!.object!.key!.replace(/\+/g, " ")), region: r.awsRegion }))
    // Digest files prove integrity; they hold no events.
    .filter((o) => !o.key.includes("/CloudTrail-Digest/"));
}

async function s3Get(ctx: ConnectorCtx, region: string, bucket: string, key: string): Promise<unknown[]> {
  const path = key.split("/").map(awsEncode).join("/");
  // Bucket names with dots break virtual-hosted TLS: use path style for those.
  const url = bucket.includes(".") ? `https://s3.${region}.amazonaws.com/${bucket}/${path}` : `https://${bucket}.s3.${region}.amazonaws.com/${path}`;
  const headers = signAws({ method: "GET", url, region, service: "s3", now: new Date(), contentSha256Header: true }, awsCredentials(ctx));
  const res = await ctx.http<Buffer>(url, { headers, binary: true });
  const buf = res.data;
  const text = buf[0] === 0x1f && buf[1] === 0x8b ? gunzipSync(buf, { maxOutputLength: 200 * 1024 * 1024 }).toString("utf8") : buf.toString("utf8");
  return asList((JSON.parse(text) as { Records?: unknown[] }).Records);
}

export const cloudtrailCollector: Collector = {
  key: "aws_cloudtrail",
  label: "AWS CloudTrail",
  tools: ["aws_cloudtrail"],
  fields: [
    { key: "region", label: "Region", required: true, placeholder: "ap-south-1" },
    { key: "queueUrl", label: "SQS queue URL", required: true, placeholder: "https://sqs.ap-south-1.amazonaws.com/111122223333/helios-cloudtrail" },
    { key: "accessKeyId", label: "Access key ID", required: true },
    { key: "secretAccessKey", label: "Secret access key", secret: true, required: true, hint: "An IAM user allowed sqs:ReceiveMessage and sqs:DeleteMessage on the queue, s3:GetObject on the trail bucket, and kms:Decrypt if the trail is KMS-encrypted" },
  ],
  docs: "Amazon SQS API (JSON protocol): ReceiveMessage, DeleteMessageBatch · Amazon S3: GetObject · Signature Version 4",
  streams: [
    {
      key: "aws.cloudtrail",
      label: "Trail log files",
      format: "cloudtrail",
      permissions: "sqs:ReceiveMessage, sqs:DeleteMessage, s3:GetObject (and kms:Decrypt for SSE-KMS)",
      everyMs: MINUTE,
      initialLookbackMs: 0,
      async poll(ctx, _cursor, { test }) {
        const { region, queueUrl } = ctx.config;
        if (!region || !queueUrl) throw new ConnectorError("Set the region and the SQS queue URL", null);
        // A test hands messages straight back (visibility 0) and reads one file.
        const received = await sqs<{ Messages?: SqsMessage[] }>(ctx, region, "ReceiveMessage", { QueueUrl: queueUrl, MaxNumberOfMessages: test ? 1 : 10, WaitTimeSeconds: 0, VisibilityTimeout: test ? 0 : 300 });
        const messages = received.Messages ?? [];
        const records: unknown[] = [];
        for (const m of messages) {
          for (const o of s3Objects(m.Body).slice(0, test ? 1 : undefined)) records.push(...(await s3Get(ctx, o.region ?? region, o.bucket, o.key)));
        }
        return {
          records: test ? records.slice(0, 5) : records,
          cursor: null,
          more: !test && messages.length >= 10,
          commit: test || !messages.length ? undefined : async () => {
            await sqs(ctx, region, "DeleteMessageBatch", { QueueUrl: queueUrl, Entries: messages.map((m, i) => ({ Id: String(i), ReceiptHandle: m.ReceiptHandle })) });
          },
        };
      },
    },
  ],
};
