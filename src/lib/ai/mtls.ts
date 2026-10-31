import { readFileSync } from "node:fs";
import { rootCertificates } from "node:tls";

import { Agent, fetch as undiciFetch } from "undici";

// Mutual TLS to on-premises model servers (the HELIOS AI box): HELIOS shows
// a client certificate from the MSSP's own CA, and a box set to require one
// (deploy/edge-ai/tls.caddy) turns away anything else before a request is
// read. One certificate for every box; each box trusts the MSSP's CA.
//
//   HELIOS_AI_CLIENT_CERT, HELIOS_AI_CLIENT_KEY  PEM files (deploy/edge-ai/make-certs.sh)
//   HELIOS_AI_CA                                 optional: a CA to trust for
//                                                boxes on Caddy's own certificates

let cached: { id: string; fetch: typeof fetch } | null = null;

export function mtlsConfigured() {
  return !!(process.env.HELIOS_AI_CLIENT_CERT && process.env.HELIOS_AI_CLIENT_KEY);
}

// The fetch to reach local model servers with, or undefined when no client
// certificate is configured.
export function localModelFetch(): typeof fetch | undefined {
  const cert = process.env.HELIOS_AI_CLIENT_CERT;
  const key = process.env.HELIOS_AI_CLIENT_KEY;
  const ca = process.env.HELIOS_AI_CA;
  if (!cert || !key) return undefined;
  const id = `${cert}|${key}|${ca ?? ""}`;
  if (cached?.id === id) return cached.fetch;
  const agent = new Agent({
    connect: {
      cert: readFileSync(cert),
      key: readFileSync(key),
      // A CA given here is trusted alongside the public ones, not instead.
      ...(ca ? { ca: [...rootCertificates, readFileSync(ca, "utf8")] } : {}),
    },
  });
  const f = ((input: string | URL | Request, init?: RequestInit) =>
    undiciFetch(input as Parameters<typeof undiciFetch>[0], { ...(init as Parameters<typeof undiciFetch>[1]), dispatcher: agent })) as unknown as typeof fetch;
  cached = { id, fetch: f };
  return f;
}
