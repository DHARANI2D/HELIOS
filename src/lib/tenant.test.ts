import { describe, it, expect } from "vitest";

import { isPlatformRole, tenantWhere } from "./tenant-scope";
import type { TenantContext } from "./tenant-scope";

function ctx(role: TenantContext["role"], organizationId: string | null): TenantContext {
  return { userId: "u1", role, organizationId };
}

describe("isPlatformRole", () => {
  it("is true for PLATFORM_OWNER and PLATFORM_ANALYST", () => {
    expect(isPlatformRole("PLATFORM_OWNER")).toBe(true);
    expect(isPlatformRole("PLATFORM_ANALYST")).toBe(true);
  });

  it("is false for every org role", () => {
    expect(isPlatformRole("ORG_ADMIN")).toBe(false);
    expect(isPlatformRole("ORG_ANALYST")).toBe(false);
    expect(isPlatformRole("ORG_VIEWER")).toBe(false);
  });
});

describe("tenantWhere", () => {
  it("returns an unscoped filter for platform roles — the 'see every tenant' view", () => {
    expect(tenantWhere(ctx("PLATFORM_OWNER", null))).toEqual({});
    expect(tenantWhere(ctx("PLATFORM_ANALYST", null))).toEqual({});
  });

  it("pins org roles to their own organizationId", () => {
    expect(tenantWhere(ctx("ORG_ADMIN", "org-1"))).toEqual({ organizationId: "org-1" });
    expect(tenantWhere(ctx("ORG_ANALYST", "org-2"))).toEqual({ organizationId: "org-2" });
    expect(tenantWhere(ctx("ORG_VIEWER", "org-3"))).toEqual({ organizationId: "org-3" });
  });

  it("never falls back to an unscoped filter for an org role, even with a null organizationId", () => {
    // Shouldn't happen by construction (org roles always have an org), but
    // if it did, this must NOT silently become `{}` (which would leak
    // every tenant's data) — it has to fail closed instead.
    const result = tenantWhere(ctx("ORG_ADMIN", null));
    expect(result).not.toEqual({});
    expect(result.organizationId).toBeTruthy();
  });
});
