"use client";

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table";
import { Loader2 } from "lucide-react";
import type { Case } from "@prisma/client";

import { listEmailCasesAction } from "@/app/(app)/forensics/actions";
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
import { EmailCaseDetailDialog } from "@/components/forensics/email-case-detail-dialog";

const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, Case>();

const columns = columnHelper.columns([
  columnHelper.accessor("title", { header: "Subject" }),
  columnHelper.accessor("severity", {
    header: "Severity",
    cell: (ctx) => (
      <Badge variant={SEVERITY_BADGE_VARIANT[ctx.getValue()]}>{SEVERITY_LABEL[ctx.getValue()]}</Badge>
    ),
  }),
  columnHelper.accessor("verdict", {
    header: "Verdict",
    cell: (ctx) => <span className="capitalize">{ctx.getValue() ?? "—"}</span>,
  }),
  columnHelper.accessor("riskScore", {
    header: "Score",
    cell: (ctx) => (ctx.getValue() != null ? Math.round(ctx.getValue()!) : "—"),
  }),
  columnHelper.accessor("createdAt", {
    header: "Analyzed",
    cell: (ctx) => new Date(ctx.getValue()).toLocaleString(),
  }),
]);

const EMPTY_DATA: Case[] = [];

export function EmailCaseTable() {
  const [openId, setOpenId] = React.useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["email-cases"],
    queryFn: () => listEmailCasesAction(),
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
        No emails analyzed yet — upload one above.
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

      <EmailCaseDetailDialog caseId={openId} onClose={() => setOpenId(null)} />
    </>
  );
}
