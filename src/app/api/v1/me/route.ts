import { authenticate, handle, json } from "@/lib/api/http";
import { PERMISSIONS, can, type Permission } from "@/lib/rbac";

// GET /api/v1/me — who the token acts as and what it may do.
export const GET = handle(async (request: Request) => {
  const p = await authenticate(request);
  return json({
    user: { id: p.id, email: p.email, name: p.name, role: p.role, client: p.tenantId ? { id: p.tenantId, name: p.tenantName } : null, domains: p.domains },
    token: { id: p.tokenId, canWrite: p.canWrite },
    permissions: (Object.keys(PERMISSIONS) as Permission[]).filter((perm) => can(p, perm)),
  });
});
