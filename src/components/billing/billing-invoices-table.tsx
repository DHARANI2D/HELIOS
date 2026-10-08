import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import type { getMyBillingAction } from "@/app/(app)/billing/actions";

type Invoice = Awaited<ReturnType<typeof getMyBillingAction>>["invoices"][number];

export function BillingInvoicesTable({ invoices }: { invoices: Invoice[] }) {
  if (!invoices.length) {
    return (
      <p className="py-10 text-center text-sm text-muted-foreground">No invoices yet.</p>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Number</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Amount</TableHead>
          <TableHead>Due</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {invoices.map((inv) => (
          <TableRow key={inv.id}>
            <TableCell>{inv.number}</TableCell>
            <TableCell>
              <Badge variant={inv.status === "PAID" ? "default" : "outline"}>{inv.status}</Badge>
            </TableCell>
            <TableCell>
              {inv.currency} {inv.totalAmount}
            </TableCell>
            <TableCell>{new Date(inv.dueDate).toLocaleDateString()}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
