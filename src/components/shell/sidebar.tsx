"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldHalf, ChevronsLeft, ChevronsRight } from "lucide-react";
import type { UserRole } from "@prisma/client";

import { NAV_GROUPS, navFor, navItemFor } from "@/lib/nav";
import { useUIStore } from "@/lib/stores/ui-store";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

export function AppSidebar({ role, tenantName }: { role: UserRole; tenantName: string | null }) {
  const pathname = usePathname();
  const { sidebarCollapsed, toggleSidebar } = useUIStore();
  const items = navFor(role);
  const active = navItemFor(pathname, items);

  return (
    <aside
      className={cn(
        "no-print hidden h-full shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground transition-[width] duration-200 md:flex",
        sidebarCollapsed ? "w-16" : "w-64",
      )}
    >
      <div className="flex h-14 items-center gap-2.5 border-b border-sidebar-border px-4">
        <div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-sidebar-primary to-sidebar-primary/60 text-sidebar-primary-foreground shadow-[0_0_18px_-4px_var(--sidebar-primary)]">
          <ShieldHalf className="size-4" />
        </div>
        {!sidebarCollapsed && (
          <div className="min-w-0 leading-tight">
            <p className="text-sm font-semibold tracking-tight">HELIOS</p>
            <p className="truncate text-[11px] text-sidebar-foreground/55">{tenantName ?? "Managed detection & response"}</p>
          </div>
        )}
      </div>

      <nav className="flex-1 overflow-y-auto px-2 py-3">
        {NAV_GROUPS.map((group) => {
          const groupItems = items.filter((i) => i.group === group);
          if (groupItems.length === 0) return null;
          return (
            <div key={group} className="mb-4">
              {!sidebarCollapsed && (
                <p className="mb-1 px-2.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-sidebar-foreground/40">{group}</p>
              )}
              <div className="space-y-0.5">
                {groupItems.map((item) => {
                  const isActive = active?.href === item.href;
                  const Icon = item.icon;
                  const link = (
                    <Link
                      key={item.href}
                      href={item.href}
                      aria-current={isActive ? "page" : undefined}
                      className={cn(
                        "relative flex items-center gap-3 rounded-md px-2.5 py-1.5 text-sm font-medium transition-colors",
                        isActive
                          ? "bg-sidebar-accent text-sidebar-accent-foreground before:absolute before:inset-y-1.5 before:left-0 before:w-0.5 before:rounded-full before:bg-sidebar-primary"
                          : "text-sidebar-foreground/70 hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground",
                        sidebarCollapsed && "justify-center px-0",
                      )}
                    >
                      <Icon className={cn("size-4 shrink-0", isActive && "text-sidebar-primary")} />
                      {!sidebarCollapsed && <span className="truncate">{item.title}</span>}
                    </Link>
                  );
                  if (!sidebarCollapsed) return link;
                  return (
                    <Tooltip key={item.href}>
                      <TooltipTrigger asChild>{link}</TooltipTrigger>
                      <TooltipContent side="right">{item.title}</TooltipContent>
                    </Tooltip>
                  );
                })}
              </div>
            </div>
          );
        })}
      </nav>

      <div className="border-t border-sidebar-border p-2">
        <Button
          variant="ghost"
          size="icon"
          className="w-full text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
          onClick={toggleSidebar}
          aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {sidebarCollapsed ? <ChevronsRight /> : <ChevronsLeft />}
        </Button>
      </div>
    </aside>
  );
}
