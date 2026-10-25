// The HTTP client native connectors use: JSON in and out, a timeout, a
// couple of retries when the vendor says "slow down" (429/503, honouring
// Retry-After), and errors that say which vendor call failed and how.
// Tokens are cached per integration until shortly before they expire.

export class ConnectorError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
  ) {
    super(message);
  }
}

export interface HttpRequest {
  method?: string;
  headers?: Record<string, string>;
  json?: unknown;
  form?: Record<string, string>;
  // Statuses that are answers rather than failures (e.g. 404 = not found).
  expect?: number[];
}

export interface HttpResponse<T = unknown> {
  status: number;
  data: T;
  headers: Headers;
}

export type Http = <T = unknown>(url: string, req?: HttpRequest) => Promise<HttpResponse<T>>;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function createHttp(fetchImpl: typeof fetch = fetch, opts: { retries?: number; timeoutMs?: number; maxWaitMs?: number } = {}): Http {
  const retries = opts.retries ?? 2;
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const maxWaitMs = opts.maxWaitMs ?? 10_000;
  return async function http<T>(url: string, req: HttpRequest = {}): Promise<HttpResponse<T>> {
    const headers: Record<string, string> = { accept: "application/json", ...(req.headers ?? {}) };
    let body: string | undefined;
    if (req.json !== undefined) {
      headers["content-type"] = "application/json";
      body = JSON.stringify(req.json);
    } else if (req.form) {
      headers["content-type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams(req.form).toString();
    }
    for (let attempt = 0; ; attempt++) {
      let res: Response;
      try {
        res = await fetchImpl(url, { method: req.method ?? (body ? "POST" : "GET"), headers, body, signal: AbortSignal.timeout(timeoutMs) });
      } catch (err) {
        throw new ConnectorError(`${new URL(url).host} unreachable: ${err instanceof Error ? err.message : String(err)}`, null);
      }
      if ((res.status === 429 || res.status === 503) && attempt < retries) {
        const after = Number(res.headers.get("retry-after"));
        await sleep(Math.min(maxWaitMs, Number.isFinite(after) && after > 0 ? after * 1000 : 500 * 2 ** attempt));
        continue;
      }
      const text = await res.text();
      let data: unknown = text;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        // not JSON; keep the text
      }
      if (!res.ok && !(req.expect ?? []).includes(res.status)) {
        const detail = typeof data === "object" && data ? JSON.stringify(data).slice(0, 300) : String(text).slice(0, 300);
        throw new ConnectorError(`${new URL(url).host} answered HTTP ${res.status}${detail ? `: ${detail}` : ""}`, res.status);
      }
      return { status: res.status, data: data as T, headers: res.headers };
    }
  };
}

const tokens = new Map<string, { token: string; expiresAt: number }>();

// A bearer token from the cache, or a fresh one (kept until a minute
// before it expires).
export async function cachedToken(key: string, fetchToken: () => Promise<{ token: string; expiresIn: number }>): Promise<string> {
  const hit = tokens.get(key);
  if (hit && hit.expiresAt > Date.now() + 60_000) return hit.token;
  const { token, expiresIn } = await fetchToken();
  tokens.set(key, { token, expiresAt: Date.now() + expiresIn * 1000 });
  return token;
}

export function forgetToken(key: string) {
  tokens.delete(key);
}

// OAuth 2.0 client credentials against Microsoft Entra ID (used for
// Defender for Endpoint and Microsoft Graph).
export async function microsoftToken(ctx: { http: Http; cacheKey: string; config: Record<string, string>; secrets: Record<string, string> }, scope: string) {
  const { tenantId, clientId } = ctx.config;
  const { clientSecret } = ctx.secrets;
  if (!tenantId || !clientId || !clientSecret) throw new ConnectorError("Set the directory (tenant) ID, application (client) ID and client secret", null);
  return cachedToken(`${ctx.cacheKey}:${scope}`, async () => {
    const res = await ctx.http<{ access_token: string; expires_in: number }>(`https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`, {
      form: { client_id: clientId, client_secret: clientSecret, grant_type: "client_credentials", scope },
    });
    return { token: res.data.access_token, expiresIn: Number(res.data.expires_in) || 3600 };
  });
}

// OData string literals double their single quotes.
export const odata = (s: string) => s.replace(/'/g, "''");
