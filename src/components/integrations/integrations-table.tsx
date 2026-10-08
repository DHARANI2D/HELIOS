"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Trash2 } from "lucide-react";

import { listIntegrationsAction, deleteIntegrationAction } from "@/app/(app)/integrations/actions";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

type IntegrationRow = Awaited<ReturnType<typeof listIntegrationsAction>>[number];

const STATUS_VARIANT: Record<string, "default" | "outline" | "destructive"> = {
  CONNECTED: "default",
  DISCONNECTED: "outline",
  ERROR: "destructive",
};

export function IntegrationsTable({ initialData }: { initialData: IntegrationRow[] }) {
  const queryClient = useQueryClient();
  const { data } = useQuery({
    queryKey: ["integrations"],
    queryFn: () => listIntegrationsAction(),
    initialData,
    refetchInterval: 15000,
  });

  const remove = useMutation({
    mutationFn: (id: string) => deleteIntegrationAction(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["integrations"] }),
  });

  if (!data.length) {
    return (
      <p className="py-10 text-center text-sm text-muted-foreground">
        No integrations yet — connect a tool above.
      </p>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Name</TableHead>
          <TableHead>Category</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Last event</TableHead>
          <TableHead />
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.map((i) => (
          <TableRow key={i.id}>
            <TableCell className="font-medium">{i.vendorLabel}</TableCell>
            <TableCell>{i.category}</TableCell>
            <TableCell>
              <Badge variant={STATUS_VARIANT[i.status] ?? "outline"}>{i.status}</Badge>
            </TableCell>
            <TableCell>{i.lastIngestAt ? new Date(i.lastIngestAt).toLocaleString() : "Never"}</TableCell>
            <TableCell>
              <Button size="icon" variant="ghost" onClick={() => remove.mutate(i.id)}>
                <Trash2 className="size-4" />
              </Button>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
