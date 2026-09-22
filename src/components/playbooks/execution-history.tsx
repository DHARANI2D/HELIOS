"use client";

import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";

import { listExecutionsAction } from "@/app/(app)/playbooks/actions";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

const STATUS_VARIANT: Record<string, "secondary" | "destructive" | "outline" | "warning"> = {
  SUCCEEDED: "secondary",
  FAILED: "destructive",
  REJECTED: "destructive",
  PENDING_APPROVAL: "warning",
  RUNNING: "outline",
};

export function ExecutionHistory() {
  const { data, isLoading } = useQuery({
    queryKey: ["executions"],
    queryFn: () => listExecutionsAction(),
    refetchInterval: 10000,
  });

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
        No playbook executions yet.
      </p>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Playbook</TableHead>
          <TableHead>Case</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Started</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.map((exec) => (
          <TableRow key={exec.id}>
            <TableCell>{exec.playbook.name}</TableCell>
            <TableCell className="max-w-xs truncate">{exec.case.title}</TableCell>
            <TableCell>
              <Badge variant={STATUS_VARIANT[exec.status] ?? "outline"}>{exec.status}</Badge>
            </TableCell>
            <TableCell>{new Date(exec.startedAt).toLocaleString()}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
