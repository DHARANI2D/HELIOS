import { NextResponse } from "next/server";

import { auth } from "@/lib/auth";

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

  if (isApiAuthRoute || isMachineRoute || isPublicPage) return;

  // Visitors who aren't signed in see the website at the root; signed-in
  // users get their dashboard there.
  if (!isLoggedIn && pathname === "/") return NextResponse.rewrite(new URL(`/home${search}`, origin));

  if (!isLoggedIn && !isAuthRoute) {
    const loginUrl = new URL("/login", origin);
    loginUrl.searchParams.set("callbackUrl", pathname);
    return Response.redirect(loginUrl);
  }

  if (isLoggedIn && isAuthRoute) {
    return Response.redirect(new URL("/", origin));
  }
});

export const config = {
  // Static assets and the install metadata (icons, manifest) load before
  // sign-in, so they skip the auth redirect.
  matcher: ["/((?!_next/static|_next/image|icon.svg|apple-icon.png|manifest.webmanifest|icons/).*)"],
};
