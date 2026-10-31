import { NextResponse } from "next/server";

import { auth } from "@/lib/auth";
import { contentSecurityPolicy, HSTS, newNonce, servedOverHttps } from "@/lib/security-headers";

// The public website: the home page and the price estimator.
const PUBLIC_PAGES = ["/home", "/estimate"];

export default auth((req) => {
  const { pathname, search, origin } = req.nextUrl;
  const isLoggedIn = !!req.auth;
  const isAuthRoute = pathname.startsWith("/login");
  const isApiAuthRoute = pathname.startsWith("/api/auth");
  // Machine-to-machine routes authenticate themselves (ingest, agent and
  // API tokens) and must never be redirected to the login page.
  const isMachineRoute = ["/api/ingest/", "/api/health", "/api/threat-intel/blocklist", "/api/governance/evaluate", "/api/v1/"].some((p) => pathname.startsWith(p));
  const isPublicPage = PUBLIC_PAGES.some((p) => pathname === p || pathname.startsWith(`${p}/`));

  if (isApiAuthRoute || isMachineRoute) return;
  if (isPublicPage) return withPolicy(req.headers);

  // Visitors who aren't signed in go to the website; signed-in users get
  // their dashboard at the root. (A redirect, not a rewrite: the auth
  // wrapper rebuilds the request URL from AUTH_URL, so a rewrite would be
  // treated as a proxy to another origin.)
  if (!isLoggedIn && pathname === "/") return Response.redirect(new URL(`/home${search}`, origin));

  if (!isLoggedIn && !isAuthRoute) {
    const loginUrl = new URL("/login", origin);
    loginUrl.searchParams.set("callbackUrl", pathname);
    return Response.redirect(loginUrl);
  }

  if (isLoggedIn && isAuthRoute) {
    return Response.redirect(new URL("/", origin));
  }
  return withPolicy(req.headers);
});

// Pages get a Content Security Policy with a fresh nonce. The policy goes
// on the request too: Next.js reads the nonce from it and adds it to the
// scripts it renders, and the root layout adds it to the theme script.
function withPolicy(requestHeaders: Headers) {
  const nonce = newNonce();
  const policy = contentSecurityPolicy(nonce);
  const headers = new Headers(requestHeaders);
  headers.set("x-nonce", nonce);
  headers.set("Content-Security-Policy", policy);
  const res = NextResponse.next({ request: { headers } });
  res.headers.set("Content-Security-Policy", policy);
  if (servedOverHttps()) res.headers.set("Strict-Transport-Security", HSTS);
  return res;
}

export const config = {
  // Static assets and the install metadata (icons, manifest) load before
  // sign-in, so they skip the auth redirect.
  matcher: ["/((?!_next/static|_next/image|icon.svg|apple-icon.png|manifest.webmanifest|icons/).*)"],
};
