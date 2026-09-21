import { redirect } from "next/navigation";

import { auth } from "@/lib/auth";
import { AppSidebar } from "@/components/shell/sidebar";
import { AppTopbar } from "@/components/shell/topbar";

export default async function AppShellLayout({
  children,
}: LayoutProps<"/">) {
  const session = await auth();
  if (!session) redirect("/login");

  return (
    <div className="flex h-screen overflow-hidden">
      <AppSidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <AppTopbar />
        <main className="flex-1 overflow-y-auto bg-muted/20 p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
