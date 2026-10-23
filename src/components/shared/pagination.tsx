import Link from "next/link";
import { ChevronLeft, ChevronRight } from "lucide-react";

import { Button } from "@/components/ui/button";

interface PaginationProps {
  page: number;
  pageSize: number;
  total: number;
  // Current query string params, so filters survive paging.
  params: Record<string, string | undefined>;
  basePath: string;
}

function href(basePath: string, params: PaginationProps["params"], page: number) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v);
  qs.set("page", String(page));
  return `${basePath}?${qs.toString()}`;
}

export function Pagination({ page, pageSize, total, params, basePath }: PaginationProps) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);

  return (
    <div className="flex items-center justify-between gap-2 pt-3 text-xs text-muted-foreground">
      <span className="tabular-nums">
        {from}–{to} of {total}
      </span>
      <div className="flex gap-1">
        {page > 1 ? (
          <Button variant="outline" size="sm" asChild>
            <Link href={href(basePath, params, page - 1)}>
              <ChevronLeft /> Prev
            </Link>
          </Button>
        ) : (
          <Button variant="outline" size="sm" disabled>
            <ChevronLeft /> Prev
          </Button>
        )}
        {page < pages ? (
          <Button variant="outline" size="sm" asChild>
            <Link href={href(basePath, params, page + 1)}>
              Next <ChevronRight />
            </Link>
          </Button>
        ) : (
          <Button variant="outline" size="sm" disabled>
            Next <ChevronRight />
          </Button>
        )}
      </div>
    </div>
  );
}

export function parsePage(value: string | string[] | undefined): number {
  const n = Number(Array.isArray(value) ? value[0] : value);
  return Number.isInteger(n) && n > 0 ? n : 1;
}
