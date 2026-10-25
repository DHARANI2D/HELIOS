import type { PlaybookActionType } from "@prisma/client";

import type { Http } from "@/lib/connectors/http";

// The contract every native response connector meets. A connector calls the
// vendor's API with the client's own least-privilege credentials:
//   preflight — the target exists, is reachable and isn't already in state;
//   execute   — ask the vendor to act, with an idempotency key, returning
//               the vendor's reference for the request;
//   verify    — read the vendor's state back. Only "confirmed" counts:
//               until then the action is in progress, and a case is never
//               contained on a request alone.
// Rollback is the inverse action through the same contract (release,
// unblock, re-enable). Pure apart from the injected HTTP client, so each
// connector is tested against recorded response shapes.

export interface ConnectorField {
  key: string;
  label: string;
  secret?: boolean;
  required?: boolean;
  placeholder?: string;
  hint?: string;
}

export interface ConnectorCtx {
  config: Record<string, string>;
  secrets: Record<string, string>;
  http: Http;
  // Caches tokens per integration.
  cacheKey: string;
}

export interface ConnectorRequest {
  action: PlaybookActionType;
  target: string;
  idempotencyKey: string;
  comment: string;
  ctx: ConnectorCtx;
}

export interface Resolved {
  id: string;
  name: string;
  state?: string;
}

export type Preflight = { ok: true; resolved: Resolved; alreadyDone?: boolean } | { ok: false; reason: string };

// The vendor's handle on a request, stored on the response action so
// verification (and a retry) can find it again.
export type VendorRef = Record<string, string>;

export interface Execution {
  ref: VendorRef;
  // Some APIs confirm synchronously (an account disabled, a rule created).
  confirmed: boolean;
  message: string;
}

export interface Verification {
  state: "confirmed" | "pending" | "failed";
  message: string;
}

export interface NativeConnector {
  key: string;
  label: string;
  // Catalog tools it serves.
  tools: string[];
  fields: ConnectorField[];
  actions: PlaybookActionType[];
  // The documentation each call was written against; check it before production.
  docs: string;
  check(ctx: ConnectorCtx): Promise<{ ok: boolean; message: string }>;
  preflight(req: ConnectorRequest): Promise<Preflight>;
  execute(req: ConnectorRequest, resolved: Resolved): Promise<Execution>;
  verify(req: Omit<ConnectorRequest, "idempotencyKey" | "comment">, ref: VendorRef): Promise<Verification>;
}
