"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check } from "lucide-react";

import { listAllInvoicesAction, setInvoiceStatusAction } from "@/app/(app)/admin/billing/actions";
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

type InvoiceRow = Awaited<ReturnType<typeof listAllInvoicesAction>>[number];

export function InvoicesTable({ initialData }: { initialData: InvoiceRow[] }) {
  const queryClient = useQueryClient();
  const { data } = useQuery({
    queryKey: ["admin-invoices"],
    queryFn: () => listAllInvoicesAction(),
    initialData,
    refetchInterval: 15000,
  });

  const markPaid = useMutation({
    mutationFn: (id: string) => setInvoiceStatusAction(id, "PAID"),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin-invoices"] }),
  });

  if (!data.length) {
    return (
      <p className="py-10 text-center text-sm text-muted-foreground">
        No invoices yet — create one from an organization&apos;s detail page.
      </p>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Number</TableHead>
          <TableHead>Organization</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Amount</TableHead>
          <TableHead>Due</TableHead>
          <TableHead />
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.map((inv) => (
          <TableRow key={inv.id}>
            <TableCell>{inv.number}</TableCell>
            <TableCell>{inv.organization.name}</TableCell>
            <TableCell>
              <Badge variant={inv.status === "PAID" ? "default" : "outline"}>{inv.status}</Badge>
            </TableCell>
            <TableCell>
              {inv.currency} {inv.totalAmount.toString()}
            </TableCell>
            <TableCell>{new Date(inv.dueDate).toLocaleDateString()}</TableCell>
            <TableCell>
              {inv.status !== "PAID" && (
                <Button size="sm" variant="outline" onClick={() => markPaid.mutate(inv.id)}>
                  <Check className="size-3.5" /> Mark paid
                </Button>
              )}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
