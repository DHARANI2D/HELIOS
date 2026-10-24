"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Building2, CornerDownLeft, Globe2, Laptop, Search, ShieldAlert } from "lucide-react";
import type { UserRole } from "@prisma/client";

import { navFor } from "@/lib/nav";
import { useUIStore } from "@/lib/stores/ui-store";
import { globalSearchAction, type SearchHit } from "@/app/(app)/shell-actions";
import { cn } from "@/lib/utils";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";

const HIT_ICON: Record<SearchHit["kind"], typeof Search> = {
  case: ShieldAlert,
  endpoint: Laptop,
  indicator: Globe2,
  tenant: Building2,
};

interface Row {
  key: string;
  title: string;
  subtitle: string;
  href: string;
  icon: typeof Search;
  section: string;
}

// ⌘K / Ctrl+K: jump to any page the role can open, or search cases,
// endpoints, indicators and clients.
export function CommandPalette({ role }: { role: UserRole }) {
  const router = useRouter();
  const open = useUIStore((s) => s.commandPaletteOpen);
  const setOpen = useUIStore((s) => s.setCommandPaletteOpen);
  const [query, setQuery] = React.useState("");
  const [hits, setHits] = React.useState<SearchHit[]>([]);
  const [cursor, setCursor] = React.useState(0);

  React.useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen(!useUIStore.getState().commandPaletteOpen);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setOpen]);

  React.useEffect(() => {
    const q = query.trim();
    if (q.length < 2) return;
    let cancelled = false;
    const timer = setTimeout(async () => {
      const result = await globalSearchAction(q).catch(() => []);
      if (!cancelled) {
        setHits(result);
        setCursor(0);
      }
    }, 180);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [query]);

  const q = query.trim().toLowerCase();
  const pages: Row[] = navFor(role)
    .filter((item) => !q || item.title.toLowerCase().includes(q) || item.description.toLowerCase().includes(q))
    .map((item) => ({ key: item.href, title: item.title, subtitle: item.description, href: item.href, icon: item.icon, section: "Go to" }));
  const results: Row[] =
    q.length >= 2
      ? hits.map((h) => ({ key: `${h.kind}:${h.id}`, title: h.title, subtitle: h.subtitle, href: h.href, icon: HIT_ICON[h.kind], section: "Results" }))
      : [];
  const rows = [...results, ...pages];

  function go(row: Row | undefined) {
    if (!row) return;
    setOpen(false);
    setQuery("");
    setHits([]);
    router.push(row.href);
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setCursor((c) => Math.min(c + 1, rows.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setCursor((c) => Math.max(c - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      go(rows[cursor]);
    }
  }

  let lastSection = "";
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="top-[18%] translate-y-0 gap-0 overflow-hidden p-0 sm:max-w-xl" showCloseButton={false} aria-describedby={undefined}>
        <DialogTitle className="sr-only">Search HELIOS</DialogTitle>
        <div className="flex items-center gap-2 border-b px-3">
          <Search className="size-4 shrink-0 text-muted-foreground" />
          <input
            autoFocus
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setCursor(0);
            }}
            onKeyDown={onKeyDown}
            placeholder="Search cases, hosts, indicators, clients — or jump to a page"
            className="h-12 flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          />
          <kbd className="rounded border bg-muted px-1.5 font-mono text-[10px] text-muted-foreground">esc</kbd>
        </div>
        <ul className="max-h-[22rem] overflow-y-auto p-1.5" role="listbox">
          {rows.length === 0 && <li className="px-3 py-8 text-center text-sm text-muted-foreground">No matches.</li>}
          {rows.map((row, i) => {
            const header = row.section !== lastSection ? row.section : null;
            lastSection = row.section;
            return (
              <React.Fragment key={row.key}>
                {header && <li className="px-2 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{header}</li>}
                <li
                  role="option"
                  aria-selected={i === cursor}
                  onMouseMove={() => setCursor(i)}
                  onClick={() => go(row)}
                  className={cn("flex cursor-pointer items-center gap-3 rounded-md px-2 py-2", i === cursor && "bg-accent text-accent-foreground")}
                >
                  <row.icon className="size-4 shrink-0 text-muted-foreground" />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium">{row.title}</p>
                    <p className="truncate text-xs text-muted-foreground">{row.subtitle}</p>
                  </div>
                  {i === cursor && <CornerDownLeft className="size-3.5 text-muted-foreground" />}
                </li>
              </React.Fragment>
            );
          })}
        </ul>
      </DialogContent>
    </Dialog>
  );
}
