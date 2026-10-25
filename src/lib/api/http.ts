import type { Permission } from "@/lib/rbac";
import { can } from "@/lib/rbac";
import { principalForToken, type ApiPrincipal } from "@/lib/api/tokens";

// Shared plumbing for /api/v1 route handlers: bearer-token auth, read/write
// scope, the owner's permissions, a per-token rate limit, and JSON errors.

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

const RATE_LIMIT_PER_MINUTE = 300;
const hits = new Map<string, { windowStart: number; count: number }>();

function rateLimited(tokenId: string) {
  const now = Date.now();
  const entry = hits.get(tokenId);
  if (!entry || now - entry.windowStart > 60_000) {
    hits.set(tokenId, { windowStart: now, count: 1 });
    return false;
  }
  return ++entry.count > RATE_LIMIT_PER_MINUTE;
}

export async function authenticate(request: Request, need: { write?: boolean; permissions?: Permission[] } = {}): Promise<ApiPrincipal> {
  const principal = await principalForToken(request.headers.get("authorization"));
  if (!principal) throw new ApiError(401, "Missing, invalid, expired or revoked API token");
  if (rateLimited(principal.tokenId)) throw new ApiError(429, `Rate limit: ${RATE_LIMIT_PER_MINUTE} requests per minute per token`);
  if (need.write && !principal.canWrite) throw new ApiError(403, "This token is read-only");
  const missing = (need.permissions ?? []).filter((p) => !can(principal, p));
  if (missing.length) throw new ApiError(403, `The token's owner lacks: ${missing.join(", ")}`);
  return principal;
}

export function json(data: unknown, status = 200) {
  return Response.json(data, { status, headers: { "cache-control": "no-store" } });
}

// Wraps a handler so thrown ApiErrors (and validation errors) become JSON.
export function handle<A extends unknown[]>(fn: (...args: A) => Promise<Response>) {
  return async (...args: A): Promise<Response> => {
    try {
      return await fn(...args);
    } catch (err) {
      if (err instanceof ApiError) return json({ error: err.message }, err.status);
      if (err && typeof err === "object" && "issues" in err) return json({ error: "Invalid request", issues: (err as { issues: unknown }).issues }, 400);
      console.error("[api/v1]", err);
      return json({ error: "Internal error" }, 500);
    }
  };
}
