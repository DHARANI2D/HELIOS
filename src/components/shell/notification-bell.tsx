"use client";

import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AtSign, Bell, Bot, CheckCheck, Clock, Eye, Inbox, Share2, ShieldCheck, TrendingUp, UserPlus } from "lucide-react";

import { getNotificationsAction, markNotificationsReadAction } from "@/app/(app)/shell-actions";
import { formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { unwrap } from "@/lib/action-result";

const KIND_ICON: Record<string, typeof Bell> = {
  mention: AtSign,
  assigned: UserPlus,
  escalated: TrendingUp,
  shared: Share2,
  watching: Eye,
  approval: ShieldCheck,
  ai: Bot,
  sla: Clock,
  lead: Inbox,
};

export function NotificationBell() {
  const queryClient = useQueryClient();
  const { data } = useQuery({
    queryKey: ["notifications"],
    queryFn: () => unwrap(getNotificationsAction()),
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
  });
  const unread = data?.unread ?? 0;

  async function markAll() {
    await unwrap(markNotificationsReadAction());
    await queryClient.invalidateQueries({ queryKey: ["notifications"] });
  }

  async function markOne(id: string) {
    await unwrap(markNotificationsReadAction([id]));
    await queryClient.invalidateQueries({ queryKey: ["notifications"] });
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" className="relative" aria-label={unread ? `${unread} unread notifications` : "Notifications"}>
          <Bell />
          {unread > 0 && (
            <span className="absolute right-1 top-1 flex min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-semibold leading-4 text-white tabular">
              {unread > 99 ? "99+" : unread}
            </span>
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-96 p-0">
        <div className="flex items-center justify-between border-b px-3 py-2">
          <p className="text-sm font-semibold">Notifications</p>
          <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={markAll} disabled={unread === 0}>
            <CheckCheck className="size-3.5" />
            Mark all read
          </Button>
        </div>
        <div className="max-h-[26rem] overflow-y-auto">
          {!data?.items.length ? (
            <p className="px-3 py-8 text-center text-sm text-muted-foreground">You&apos;re all caught up.</p>
          ) : (
            <ul className="divide-y">
              {data.items.map((n) => {
                const Icon = KIND_ICON[n.kind] ?? Bell;
                const body = (
                  <div className={cn("flex gap-3 px-3 py-2.5 transition-colors hover:bg-accent/60", !n.read && "bg-primary/5")}>
                    <span className={cn("mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground", !n.read && "bg-primary/15 text-primary")}>
                      <Icon className="size-3.5" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className={cn("text-sm leading-snug", !n.read && "font-medium")}>{n.title}</p>
                      {n.body && <p className="mt-0.5 line-clamp-2 text-xs text-muted-foreground">{n.body}</p>}
                      <p className="mt-1 text-[11px] text-muted-foreground">
                        {n.actorName ? `${n.actorName} · ` : ""}
                        {formatRelative(new Date(n.createdAt))}
                      </p>
                    </div>
                    {!n.read && <span className="mt-2 size-2 shrink-0 rounded-full bg-primary" aria-label="Unread" />}
                  </div>
                );
                return (
                  <li key={n.id}>
                    {n.href ? (
                      <Link href={n.href} onClick={() => markOne(n.id)} className="block">
                        {body}
                      </Link>
                    ) : (
                      <button type="button" className="block w-full text-left" onClick={() => markOne(n.id)}>
                        {body}
                      </button>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
