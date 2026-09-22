"use client";

import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";

import { listAuditLogAction } from "@/app/(app)/audit/actions";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

export function AuditLogTable() {
  const { data, isLoading } = useQuery({
    queryKey: ["audit-log"],
    queryFn: () => listAuditLogAction(),
    refetchInterval: 15000,
  });

  if (isLoading) {
    return (
      <div className="flex justify-center py-10 text-muted-foreground">
        <Loader2 className="animate-spin" />
      </div>
    );
  }

  if (!data?.length) {
    return <p className="py-10 text-center text-sm text-muted-foreground">No audit entries yet.</p>;
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Action</TableHead>
          <TableHead>Actor</TableHead>
          <TableHead>Case</TableHead>
          <TableHead>Hash</TableHead>
          <TableHead>Time</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.map((entry) => (
          <TableRow key={entry.id}>
            <TableCell>
              <Badge variant="outline">{entry.action}</Badge>
            </TableCell>
            <TableCell className="text-xs text-muted-foreground">
              {entry.actor?.name ?? entry.actor?.email ?? "system"}
            </TableCell>
            <TableCell className="max-w-[200px] truncate text-xs">
              {entry.case?.title ?? "—"}
            </TableCell>
            <TableCell className="font-mono text-xs text-muted-foreground">
              {entry.currentHash.slice(0, 12)}…
            </TableCell>
            <TableCell className="text-xs">{new Date(entry.createdAt).toLocaleString()}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
