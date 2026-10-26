import { db } from "@/lib/db";
import type { SessionUser } from "@/lib/session";

// Database-enforced tenant isolation. Every query through tenantDb(id) runs
// in a transaction that first sets helios.tenant_id, so Postgres's row-level
// policies (migration 20261026070000_platform_security) return and accept
// only that client's rows on the tenant-scoped tables, even if a query
// forgets its tenant filter. It sits under the application's own filters,
// not instead of them. Staff and background work use `db` unscoped.

// Superusers bypass row-level security. Where the app's database user is
// one (or owns the tables without FORCE), HELIOS_DB_TENANT_ROLE names a
// plain role, granted the app's tables, that scoped transactions switch to.
function tenantRole() {
  const role = process.env.HELIOS_DB_TENANT_ROLE;
  if (role && !/^[a-z_][a-z0-9_]{0,62}$/.test(role)) throw new Error("HELIOS_DB_TENANT_ROLE must be a plain role name");
  return role;
}

function scoped(tenantId: string) {
  return db.$extends({
    name: "tenant-isolation",
    query: {
      $allModels: {
        async $allOperations({ args, query }) {
          const role = tenantRole();
          const setup = [db.$executeRaw`SELECT set_config('helios.tenant_id', ${tenantId}, TRUE)`, ...(role ? [db.$executeRawUnsafe(`SET LOCAL ROLE ${role}`)] : [])];
          const results = await db.$transaction([...setup, query(args)]);
          return results[results.length - 1];
        },
      },
    },
  });
}

const clients = new Map<string, ReturnType<typeof scoped>>();

export function tenantDb(tenantId: string) {
  let client = clients.get(tenantId);
  if (!client) {
    client = scoped(tenantId);
    clients.set(tenantId, client);
  }
  return client;
}

export type ScopedDb = typeof db | ReturnType<typeof tenantDb>;

// The client a request should query with: scoped for a client user, the
// platform's for staff.
export function dbFor(user: Pick<SessionUser, "isClient" | "tenantId">): ScopedDb {
  if (!user.isClient) return db;
  // A client account without a client can't see client data at all.
  return tenantDb(user.tenantId ?? "__none__");
}
