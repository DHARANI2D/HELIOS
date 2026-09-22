"use client";

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table";
import { Loader2 } from "lucide-react";
import type { ThreatIndicator } from "@prisma/client";

import { listIndicatorsAction } from "@/app/(app)/threat-intel/actions";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, ThreatIndicator>();

const columns = columnHelper.columns([
  columnHelper.accessor("type", { header: "Type" }),
  columnHelper.accessor("value", { header: "Value" }),
  columnHelper.accessor("maliciousScore", {
    header: "Score",
    cell: (ctx) => {
      const score = (ctx.getValue() ?? 0) * 100;
      return (
        <Badge variant={score > 50 ? "destructive" : "secondary"}>
          {Math.round(score)}%
        </Badge>
      );
    },
  }),
  columnHelper.accessor("lastCheckedAt", {
    header: "Last checked",
    cell: (ctx) => new Date(ctx.getValue()).toLocaleString(),
  }),
  columnHelper.accessor("expiresAt", {
    header: "Cache expires",
    cell: (ctx) => new Date(ctx.getValue()).toLocaleString(),
  }),
]);

const EMPTY_DATA: ThreatIndicator[] = [];

export function IndicatorTable() {
  const { data, isLoading } = useQuery({
    queryKey: ["threat-indicators"],
    queryFn: () => listIndicatorsAction(),
  });

  const table = useTable({ features, columns, data: data ?? EMPTY_DATA });

  if (isLoading) {
    return (
      <div className="flex justify-center py-10 text-muted-foreground">
        <Loader2 className="animate-spin" />
      </div>
    );
  }

  if (!data?.length) {
    return (
      <p className="py-10 text-center text-sm text-muted-foreground">
        No indicators cached yet — run a lookup above.
      </p>
    );
  }

  return (
    <Table>
      <TableHeader>
        {table.getHeaderGroups().map((group) => (
          <TableRow key={group.id}>
            {group.headers.map((header) => (
              <TableHead key={header.id}>
                {header.isPlaceholder ? null : <table.FlexRender header={header} />}
              </TableHead>
            ))}
          </TableRow>
        ))}
      </TableHeader>
      <TableBody>
        {table.getRowModel().rows.map((row) => (
          <TableRow key={row.id}>
            {row.getAllCells().map((cell) => (
              <TableCell key={cell.id}>
                <table.FlexRender cell={cell} />
              </TableCell>
            ))}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
