"use client";

import { usePathname } from "next/navigation";
import { signOut, useSession } from "next-auth/react";
import { LogOut, User } from "lucide-react";

import { NAV_ITEMS } from "@/lib/nav";
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

export function AppTopbar() {
  const pathname = usePathname();
  const { data: session } = useSession();

  const current =
    NAV_ITEMS.find((item) =>
      item.href === "/" ? pathname === "/" : pathname.startsWith(item.href),
    ) ?? NAV_ITEMS[0];

  const initials =
    session?.user?.name
      ?.split(" ")
      .map((part) => part[0])
      .join("")
      .slice(0, 2)
      .toUpperCase() ?? "?";

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b bg-background px-4">
      <div>
        <h1 className="text-sm font-semibold leading-none">{current.title}</h1>
        <p className="mt-0.5 text-xs text-muted-foreground">
          {current.description}
        </p>
      </div>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" className="gap-2 px-2">
            <Avatar className="size-7">
              <AvatarFallback>{initials}</AvatarFallback>
            </Avatar>
            <span className="hidden text-sm font-medium sm:inline">
              {session?.user?.name ?? session?.user?.email}
            </span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel>
            <div className="flex flex-col">
              <span className="font-medium">{session?.user?.name}</span>
              <span className="text-xs font-normal text-muted-foreground">
                {session?.user?.email}
              </span>
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem disabled>
            <User />
            Profile
          </DropdownMenuItem>
          <DropdownMenuItem
            variant="destructive"
            onClick={() => signOut({ callbackUrl: "/login" })}
          >
            <LogOut />
            Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </header>
  );
}
