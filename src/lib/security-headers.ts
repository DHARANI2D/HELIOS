// Response headers that harden every page HELIOS serves. The fixed ones
// go on every response (next.config.ts, read at build time). The Content
// Security Policy and HSTS are set per request in src/proxy.ts: the
// policy's nonce must be new each time, and whether the site is served
// over https is only known where the image runs. Next.js reads the nonce
// from the request's policy and puts it on its own scripts; the layout
// puts it on the theme script.

const isDev = () => process.env.NODE_ENV === "development";

// Set on every response, including API routes and static files.
export function staticSecurityHeaders(): Array<{ key: string; value: string }> {
  return [
    { key: "X-Content-Type-Options", value: "nosniff" },
    { key: "X-Frame-Options", value: "DENY" },
    { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
    { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()" },
    { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
    { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
    { key: "X-DNS-Prefetch-Control", value: "off" },
  ];
}

// Only when the site is served over https: a browser that sees it keeps to
// https for two years, so a plain-http test install must not send it.
export const HSTS = "max-age=63072000; includeSubDomains";
export const servedOverHttps = (env: Record<string, string | undefined> = process.env) => (env.AUTH_URL ?? "").startsWith("https://");

export function newNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

export function contentSecurityPolicy(nonce: string, env: Record<string, string | undefined> = process.env) {
  const https = servedOverHttps(env);
  return [
    "default-src 'self'",
    // Only scripts carrying this response's nonce, and what they load.
    // Development needs eval for React's debugging aids.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev() ? " 'unsafe-eval'" : ""}`,
    // Components set style attributes (positioning of menus and popovers,
    // chart sizes), which a nonce can't cover.
    "style-src 'self' 'unsafe-inline'",
    // QR codes and previews are data: and blob: URLs.
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "worker-src 'self' blob:",
    "manifest-src 'self'",
    "media-src 'self'",
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    ...(https ? ["upgrade-insecure-requests"] : []),
  ].join("; ");
}
