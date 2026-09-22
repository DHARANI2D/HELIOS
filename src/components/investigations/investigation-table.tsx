"use client";

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table";
import { Loader2 } from "lucide-react";
import type { Case } from "@prisma/client";

import { listInvestigationsAction } from "@/app/(app)/investigations/actions";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { SEVERITY_LABEL, SEVERITY_BADGE_VARIANT } from "@/lib/severity";
import { InvestigationDetailDialog } from "@/components/investigations/investigation-detail-dialog";

const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, Case>();

const columns = columnHelper.columns([
  columnHelper.accessor("title", { header: "Investigation" }),
  columnHelper.accessor("severity", {
    header: "Severity",
    cell: (ctx) => (
      <Badge variant={SEVERITY_BADGE_VARIANT[ctx.getValue()]}>{SEVERITY_LABEL[ctx.getValue()]}</Badge>
    ),
  }),
  columnHelper.accessor("status", { header: "Status" }),
  columnHelper.accessor("verdict", {
    header: "Verdict",
    cell: (ctx) => ctx.getValue() ?? "—",
  }),
  columnHelper.accessor("confidence", {
    header: "Confidence",
    cell: (ctx) => (ctx.getValue() != null ? `${Math.round(ctx.getValue()! * 100)}%` : "—"),
  }),
  columnHelper.accessor("createdAt", {
    header: "Created",
    cell: (ctx) => new Date(ctx.getValue()).toLocaleString(),
  }),
]);

const EMPTY_DATA: Case[] = [];

export function InvestigationTable() {
  const [openId, setOpenId] = React.useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["investigations"],
    queryFn: () => listInvestigationsAction(),
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
        No investigations yet — run one above.
      </p>
    );
  }

  return (
    <>
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
            <TableRow
              key={row.id}
              className="cursor-pointer"
              onClick={() => setOpenId(row.original.id)}
            >
              {row.getAllCells().map((cell) => (
                <TableCell key={cell.id}>
                  <table.FlexRender cell={cell} />
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <InvestigationDetailDialog caseId={openId} onClose={() => setOpenId(null)} />
    </>
  );
}
