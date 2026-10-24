import { db } from "@/lib/db";
import { currentUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { authenticateFeedToken } from "@/lib/integrations/service";

// Plain-text blocklist (one indicator per line) for firewalls / proxies that
// consume external threat feeds. ?type=IP|DOMAIN|URL narrows it. Signed-in
// staff can read it; devices authenticate with an onboarded tool's token
// (Authorization: Bearer <token>).
export async function GET(request: Request) {
  const user = await currentUser();
  const allowedUser = user && can(user, "intel.view");
  const device = allowedUser ? null : await authenticateFeedToken(request.headers.get("authorization"));
  if (!allowedUser && !device) return new Response("Unauthorized", { status: 401 });

  const type = new URL(request.url).searchParams.get("type")?.toUpperCase();
  const allowed = ["IP", "DOMAIN", "URL", "FILE_HASH", "EMAIL_ADDRESS"] as const;
  const filter = allowed.find((t) => t === type);

  const blocked = await db.threatIndicator.findMany({
    where: { blockedAt: { not: null }, ...(filter ? { type: filter } : {}) },
    orderBy: { blockedAt: "desc" },
    select: { value: true },
  });

  return new Response(blocked.map((b) => b.value).join("\n") + (blocked.length ? "\n" : ""), {
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}
