import { redirect } from "next/navigation";
import type { UserRole } from "@prisma/client";

import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { AppSidebar } from "@/components/shell/sidebar";
import { AppTopbar } from "@/components/shell/topbar";
import { TenantProvider } from "@/components/providers/tenant-provider";

export default async function AppShellLayout({
  children,
}: LayoutProps<"/">) {
  const session = await auth();
  if (!session?.user) redirect("/login");

  const organizationId = session.user.organizationId ?? null;
  const organization = organizationId
    ? await db.organization.findUnique({ where: { id: organizationId }, select: { name: true } })
    : null;

  return (
    <TenantProvider
      value={{
        role: session.user.role as UserRole,
        organizationId,
        organizationName: organization?.name ?? null,
      }}
    >
      <div className="flex h-screen overflow-hidden">
        <AppSidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <AppTopbar />
          <main className="flex-1 overflow-y-auto bg-muted/20 p-6">
            {children}
          </main>
        </div>
      </div>
    </TenantProvider>
  );
}
