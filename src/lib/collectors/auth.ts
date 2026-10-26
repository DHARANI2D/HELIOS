import { createHash, createHmac, createSign } from "node:crypto";

import { ConnectorError, cachedToken } from "@/lib/connectors/http";
import type { ConnectorCtx } from "@/lib/connectors/types";

// Signing for the clouds whose APIs don't take a plain bearer token or API key.

const b64url = (b: Buffer | string) => Buffer.from(b).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");

// ---------------------------------------------------------------- Google

interface ServiceAccountKey {
  client_email: string;
  private_key: string;
}

function serviceAccount(ctx: ConnectorCtx): ServiceAccountKey {
  const raw = ctx.secrets.serviceAccountKey;
  if (!raw) throw new ConnectorError("Paste the service account's JSON key", null);
  let key: Partial<ServiceAccountKey>;
  try {
    key = JSON.parse(raw);
  } catch {
    throw new ConnectorError("The service account key isn't valid JSON", null);
  }
  if (!key.client_email || !key.private_key) throw new ConnectorError("The service account key has no client_email or private_key", null);
  return key as ServiceAccountKey;
}

// OAuth 2.0 for service accounts: a JWT signed with the account's key,
// exchanged for an access token. `subject` impersonates a Workspace user
// (domain-wide delegation), which the Reports API needs.
export function googleAssertion(key: ServiceAccountKey, scope: string, subject: string | undefined, now: Date) {
  const iat = Math.floor(now.getTime() / 1000);
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = b64url(JSON.stringify({ iss: key.client_email, scope, aud: "https://oauth2.googleapis.com/token", iat, exp: iat + 3600, ...(subject ? { sub: subject } : {}) }));
  const signature = createSign("RSA-SHA256").update(`${header}.${claims}`).sign(key.private_key);
  return `${header}.${claims}.${b64url(signature)}`;
}

export async function googleToken(ctx: ConnectorCtx, scope: string, subject?: string) {
  const key = serviceAccount(ctx);
  return cachedToken(`${ctx.cacheKey}:google:${scope}:${subject ?? ""}`, async () => {
    const res = await ctx.http<{ access_token: string; expires_in: number }>("https://oauth2.googleapis.com/token", {
      form: { grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: googleAssertion(key, scope, subject, new Date()) },
    });
    return { token: res.data.access_token, expiresIn: Number(res.data.expires_in) || 3600 };
  });
}

// ---------------------------------------------------------------- AWS Signature Version 4

const sha256 = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");
const hmac = (key: Buffer | string, data: string) => createHmac("sha256", key).update(data).digest();

// RFC 3986 encoding, as SigV4 canonical requests want it.
export const awsEncode = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export interface SignInput {
  method: string;
  url: string;
  region: string;
  service: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
  now: Date;
  // S3 wants the payload hash as a header too.
  contentSha256Header?: boolean;
}

export function signAws(input: SignInput, creds: AwsCredentials): Record<string, string> {
  const u = new URL(input.url);
  const amzDate = input.now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const date = amzDate.slice(0, 8);
  const payloadHash = sha256(input.body ?? "");
  const headers: Record<string, string> = { host: u.host, "x-amz-date": amzDate };
  for (const [k, v] of Object.entries(input.headers ?? {})) headers[k.toLowerCase()] = v;
  if (input.contentSha256Header) headers["x-amz-content-sha256"] = payloadHash;
  if (creds.sessionToken) headers["x-amz-security-token"] = creds.sessionToken;
  const names = Object.keys(headers).sort();
  const canonicalHeaders = names.map((k) => `${k}:${headers[k].trim().replace(/\s+/g, " ")}\n`).join("");
  const signedHeaders = names.join(";");
  const query = [...u.searchParams.entries()].map(([k, v]) => [awsEncode(k), awsEncode(v)]).sort(([a, av], [b, bv]) => (a === b ? (av < bv ? -1 : 1) : a < b ? -1 : 1)).map(([k, v]) => `${k}=${v}`).join("&");
  const canonical = [input.method, u.pathname || "/", query, canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const scope = `${date}/${input.region}/${input.service}/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonical)].join("\n");
  const key = hmac(hmac(hmac(hmac(`AWS4${creds.secretAccessKey}`, date), input.region), input.service), "aws4_request");
  const signature = createHmac("sha256", key).update(toSign).digest("hex");
  const { host: _host, ...rest } = headers;
  return { ...rest, authorization: `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}` };
}

export function awsCredentials(ctx: ConnectorCtx): AwsCredentials {
  const { accessKeyId } = ctx.config;
  const { secretAccessKey, sessionToken } = ctx.secrets;
  if (!accessKeyId || !secretAccessKey) throw new ConnectorError("Set the access key ID and secret access key", null);
  return { accessKeyId, secretAccessKey, sessionToken: sessionToken || undefined };
}
