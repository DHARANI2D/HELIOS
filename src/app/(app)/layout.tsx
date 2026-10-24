import { redirect } from "next/navigation";
import { FlaskConical } from "lucide-react";

import { db } from "@/lib/db";
import { currentUser } from "@/lib/session";
import { getSetting, platformEnvironment } from "@/lib/settings";
import { selectedTenantId } from "@/lib/access";
import { AppSidebar } from "@/components/shell/sidebar";
import { AppTopbar } from "@/components/shell/topbar";
import { NotificationBell } from "@/components/shell/notification-bell";
import { CommandPalette } from "@/components/shell/command-palette";

export default async function AppShellLayout({ children }: LayoutProps<"/">) {
  const user = await currentUser();
  if (!user) redirect("/login");

  const [tenants, selected, environment, ownTenant, company] = await Promise.all([
    user.isClient ? Promise.resolve([]) : db.tenant.findMany({ where: { status: { not: "SUSPENDED" } }, select: { id: true, name: true, isTest: true }, orderBy: { name: "asc" } }),
    selectedTenantId(user),
    platformEnvironment(),
    user.tenantId ? db.tenant.findUnique({ where: { id: user.tenantId }, select: { isTest: true } }) : Promise.resolve(null),
    getSetting("company.profile"),
  ]);
  const selectedTest = user.isClient ? !!ownTenant?.isTest : tenants.some((t) => t.id === selected && t.isTest);

  return (
    <div className="flex h-screen overflow-hidden">
      <AppSidebar role={user.role} tenantName={user.tenantName} companyName={company.name} />
      <div className="flex min-w-0 flex-1 flex-col">
        <AppTopbar
          viewer={{ name: user.name ?? null, email: user.email ?? null, role: user.role, tenantName: user.tenantName, isClient: user.isClient }}
          tenants={tenants}
          selectedTenantId={user.isClient ? null : selected}
          notifications={<NotificationBell />}
        />
        {(environment === "test" || selectedTest) && (
          <div role="status" className="flex items-center gap-2 border-b border-warning/40 bg-warning/15 px-4 py-1.5 text-xs text-foreground md:px-6">
            <FlaskConical className="size-3.5 shrink-0" />
            {environment === "test" ? (
              <span><strong>Test environment.</strong> Everything here is test data — don&apos;t onboard real clients or connect production tools.</span>
            ) : (
              <span><strong>Test client.</strong> You&apos;re looking at test data.</span>
            )}
          </div>
        )}
        <main className="flex-1 overflow-y-auto p-4 md:p-6">{children}</main>
      </div>
      <CommandPalette role={user.role} />
    </div>
  );
}
