"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldHalf, ChevronsLeft, ChevronsRight } from "lucide-react";

import { NAV_ITEMS } from "@/lib/nav";
import { useUIStore } from "@/lib/stores/ui-store";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

export function AppSidebar() {
  const pathname = usePathname();
  const { sidebarCollapsed, toggleSidebar } = useUIStore();

  return (
    <aside
      className={cn(
        "flex h-full flex-col border-r bg-sidebar text-sidebar-foreground transition-[width] duration-200",
        sidebarCollapsed ? "w-16" : "w-64",
      )}
    >
      <div className="flex h-14 items-center gap-2 border-b border-sidebar-border px-4">
        <div className="flex size-7 shrink-0 items-center justify-center rounded-md bg-sidebar-primary text-sidebar-primary-foreground">
          <ShieldHalf className="size-4" />
        </div>
        {!sidebarCollapsed && (
          <span className="text-sm font-semibold tracking-tight">HELIOS</span>
        )}
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-2 py-3">
        {NAV_ITEMS.map((item) => {
          const active =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);
          const Icon = item.icon;

          const link = (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-2.5 py-2 text-sm font-medium transition-colors",
                active
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-sidebar-foreground/70 hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground",
                sidebarCollapsed && "justify-center px-0",
              )}
            >
              <Icon className="size-4 shrink-0" />
              {!sidebarCollapsed && <span>{item.title}</span>}
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
      </nav>

      <div className="border-t border-sidebar-border p-2">
        <Button
          variant="ghost"
          size="icon"
          className="w-full"
          onClick={toggleSidebar}
          aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {sidebarCollapsed ? <ChevronsRight /> : <ChevronsLeft />}
        </Button>
      </div>
    </aside>
  );
}
