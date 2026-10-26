import { currentUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { readArchive } from "@/lib/retention/service";

// One archived day of a client's events, decrypted and checked against its
// recorded hash: gzip-compressed NDJSON, one event per line.
export async function GET(_request: Request, ctx: RouteContext<"/retention/archives/[id]">) {
  const { id } = await ctx.params;
  const user = await currentUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (user.isClient || !(can(user, "settings.manage") || can(user, "audit.export"))) return new Response("Forbidden", { status: 403 });
  try {
    const { filename, gz } = await readArchive(id, user.id);
    return new Response(new Uint8Array(gz), { headers: { "content-type": "application/gzip", "content-disposition": `attachment; filename="${filename}"`, "cache-control": "private, no-store" } });
  } catch (err) {
    return new Response(err instanceof Error ? err.message : "Can't read the archive", { status: 409 });
  }
}
