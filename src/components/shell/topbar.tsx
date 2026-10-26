"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { signOut } from "next-auth/react";
import { BellRing, Building2, KeyRound, LogOut, Menu, Search } from "lucide-react";
import type { UserRole } from "@prisma/client";

import { navFor, navItemFor, otherPageFor } from "@/lib/nav";
import { roleLabel } from "@/lib/rbac";
import { useUIStore } from "@/lib/stores/ui-store";
import { setTenantFilterAction } from "@/app/(app)/shell-actions";
import { ThemeToggle } from "@/components/shell/theme-toggle";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export interface ShellViewer {
  name: string | null;
  email: string | null;
  role: UserRole;
  tenantName: string | null;
  isClient: boolean;
}

interface TopbarProps {
  viewer: ShellViewer;
  tenants: Array<{ id: string; name: string; isTest: boolean }>;
  selectedTenantId: string | null;
  notifications?: React.ReactNode;
}

export function AppTopbar({ viewer, tenants, selectedTenantId, notifications }: TopbarProps) {
  const pathname = usePathname();
  const router = useRouter();
  const items = navFor(viewer.role);
  const current = navItemFor(pathname, items) ?? otherPageFor(pathname) ?? items[0];
  const setCommandPaletteOpen = useUIStore((s) => s.setCommandPaletteOpen);
  const [pending, startTransition] = React.useTransition();

  const initials =
    (viewer.name ?? viewer.email ?? "?")
      .split(/[\s@.]+/)
      .filter(Boolean)
      .map((part) => part[0])
      .join("")
      .slice(0, 2)
      .toUpperCase();

  function onTenantChange(value: string) {
    startTransition(async () => {
      await setTenantFilterAction(value);
      router.refresh();
    });
  }

  return (
    <header className="no-print sticky top-0 z-20 flex h-14 shrink-0 items-center justify-between gap-3 border-b bg-background/80 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/65">
      <div className="flex min-w-0 items-center gap-2">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="md:hidden" aria-label="Open navigation">
              <Menu />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-60">
            {items.map((item) => (
              <DropdownMenuItem key={item.href} asChild>
                <Link href={item.href}>
                  <item.icon />
                  {item.title}
                </Link>
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
        <div className="min-w-0">
          <h1 className="truncate text-sm font-semibold leading-none">{current?.title}</h1>
          <p className="mt-1 hidden truncate text-xs text-muted-foreground sm:block">{current?.description}</p>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          className="hidden h-8 gap-2 text-muted-foreground lg:inline-flex"
          onClick={() => setCommandPaletteOpen(true)}
        >
          <Search className="size-3.5" />
          Search or jump to…
          <kbd className="rounded border bg-muted px-1.5 font-mono text-[10px]">⌘K</kbd>
        </Button>

        {!viewer.isClient && tenants.length > 0 && (
          <label className="relative hidden items-center sm:flex">
            <span className="sr-only">Client</span>
            <Building2 className="pointer-events-none absolute left-2.5 size-3.5 text-muted-foreground" />
            <select
              value={selectedTenantId ?? "all"}
              onChange={(e) => onTenantChange(e.target.value)}
              disabled={pending}
              className="h-8 max-w-48 appearance-none truncate rounded-md border bg-background pl-8 pr-7 text-xs font-medium shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring/50 disabled:opacity-60"
            >
              <option value="all">All clients</option>
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                  {t.isTest && !/^test\b/i.test(t.name) ? " (test)" : ""}
                </option>
              ))}
            </select>
            <span className="pointer-events-none absolute right-2.5 text-[10px] text-muted-foreground">▾</span>
          </label>
        )}

        {notifications}
        <ThemeToggle className="hidden sm:inline-flex" />

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="gap-2 px-1.5">
              <Avatar className="size-7">
                <AvatarFallback className="bg-primary/15 text-xs font-semibold text-primary">{initials}</AvatarFallback>
              </Avatar>
              <span className="hidden text-left leading-tight xl:block">
                <span className="block text-sm font-medium">{viewer.name ?? viewer.email}</span>
                <span className="block text-[11px] text-muted-foreground">{roleLabel(viewer.role)}</span>
              </span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-64">
            <DropdownMenuLabel>
              <div className="flex flex-col">
                <span className="font-medium">{viewer.name}</span>
                <span className="text-xs font-normal text-muted-foreground">{viewer.email}</span>
                <span className="mt-1 text-xs font-normal text-muted-foreground">
                  {roleLabel(viewer.role)}
                  {viewer.tenantName ? ` · ${viewer.tenantName}` : ""}
                </span>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <div className="flex items-center justify-between px-2 py-1.5 sm:hidden">
              <span className="text-sm">Theme</span>
              <ThemeToggle />
            </div>
            <DropdownMenuItem asChild>
              <Link href="/account/security">
                <KeyRound />
                Sign-in security
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link href="/account/alerts">
                <BellRing />
                My alerts
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem variant="destructive" onClick={() => signOut({ callbackUrl: "/login" })}>
              <LogOut />
              Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
