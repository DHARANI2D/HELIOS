"use client";

import { createContext, useContext, type ReactNode } from "react";
import type { UserRole } from "@prisma/client";

export interface TenantInfo {
  role: UserRole;
  organizationId: string | null;
  organizationName: string | null;
}

const TenantContext = createContext<TenantInfo | null>(null);

// Populated once, server-side, in (app)/layout.tsx (which already runs
// auth() + an Organization lookup) so client components like the sidebar
// and topbar don't each re-derive role/org from useSession().
export function TenantProvider({ value, children }: { value: TenantInfo; children: ReactNode }) {
  return <TenantContext.Provider value={value}>{children}</TenantContext.Provider>;
}

export function useTenant(): TenantInfo {
  const ctx = useContext(TenantContext);
  if (!ctx) throw new Error("useTenant() must be used within a <TenantProvider>");
  return ctx;
}
