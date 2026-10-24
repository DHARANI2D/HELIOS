import { redirect } from "next/navigation";

import { db } from "@/lib/db";
import { currentUser } from "@/lib/session";
import { selectedTenantId } from "@/lib/access";
import { AppSidebar } from "@/components/shell/sidebar";
import { AppTopbar } from "@/components/shell/topbar";
import { NotificationBell } from "@/components/shell/notification-bell";
import { CommandPalette } from "@/components/shell/command-palette";

export default async function AppShellLayout({ children }: LayoutProps<"/">) {
  const user = await currentUser();
  if (!user) redirect("/login");

  const [tenants, selected] = await Promise.all([
    user.isClient ? Promise.resolve([]) : db.tenant.findMany({ where: { status: { not: "SUSPENDED" } }, select: { id: true, name: true }, orderBy: { name: "asc" } }),
    selectedTenantId(user),
  ]);

  return (
    <div className="flex h-screen overflow-hidden">
      <AppSidebar role={user.role} tenantName={user.tenantName} />
      <div className="flex min-w-0 flex-1 flex-col">
        <AppTopbar
          viewer={{ name: user.name ?? null, email: user.email ?? null, role: user.role, tenantName: user.tenantName, isClient: user.isClient }}
          tenants={tenants}
          selectedTenantId={user.isClient ? null : selected}
          notifications={<NotificationBell />}
        />
        <main className="flex-1 overflow-y-auto p-4 md:p-6">{children}</main>
      </div>
      <CommandPalette role={user.role} />
    </div>
  );
}
