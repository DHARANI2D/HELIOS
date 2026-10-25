import { auth } from "@/lib/auth";

export default auth((req) => {
  const isLoggedIn = !!req.auth;
  const isAuthRoute = req.nextUrl.pathname.startsWith("/login");
  const isApiAuthRoute = req.nextUrl.pathname.startsWith("/api/auth");
  // Machine-to-machine routes authenticate themselves (ingest, agent and
  // API tokens) and must never be redirected to the login page.
  const isMachineRoute = ["/api/ingest/", "/api/health", "/api/threat-intel/blocklist", "/api/governance/evaluate", "/api/v1/"].some((p) => req.nextUrl.pathname.startsWith(p));

  if (isApiAuthRoute || isMachineRoute) return;

  if (!isLoggedIn && !isAuthRoute) {
    const loginUrl = new URL("/login", req.nextUrl.origin);
    loginUrl.searchParams.set("callbackUrl", req.nextUrl.pathname);
    return Response.redirect(loginUrl);
  }

  if (isLoggedIn && isAuthRoute) {
    return Response.redirect(new URL("/", req.nextUrl.origin));
  }
});

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
