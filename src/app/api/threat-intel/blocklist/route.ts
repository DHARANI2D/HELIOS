import { auth } from "@/lib/auth";
import { db } from "@/lib/db";

// Plain-text blocklist (one indicator per line) for firewalls / proxies that
// consume external threat feeds. ?type=IP|DOMAIN|URL narrows it.
export async function GET(request: Request) {
  const session = await auth();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });

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
