"use client";

import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { createInvoiceForOrgAction } from "@/app/(app)/admin/organizations/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export function CreateInvoiceForm({
  organizationId,
}: {
  organizationId: string;
  subscriptions: { id: string; label: string }[];
}) {
  const [description, setDescription] = React.useState("");
  const [amount, setAmount] = React.useState("");
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () =>
      createInvoiceForOrgAction(organizationId, [
        { description: description.trim(), quantity: 1, unitPrice: Number(amount) },
      ]),
    onSuccess: () => {
      toast.success("Invoice created");
      setDescription("");
      setAmount("");
      queryClient.invalidateQueries({ queryKey: ["admin-organizations"] });
      queryClient.invalidateQueries({ queryKey: ["admin-invoices"] });
    },
    onError: () => toast.error("Failed to create invoice"),
  });

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (!description.trim() || !amount || Number(amount) <= 0) {
          toast.error("Description and a positive amount are required");
          return;
        }
        mutation.mutate();
      }}
      className="flex gap-2"
    >
      <Input
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        placeholder="e.g. October — Endpoint Security (Professional)"
        className="flex-1"
      />
      <Input
        type="number"
        min="0"
        step="0.01"
        value={amount}
        onChange={(e) => setAmount(e.target.value)}
        placeholder="Amount"
        className="w-28"
      />
      <Button type="submit" disabled={mutation.isPending}>
        {mutation.isPending ? <Loader2 className="animate-spin" /> : <Plus />}
      </Button>
    </form>
  );
}
