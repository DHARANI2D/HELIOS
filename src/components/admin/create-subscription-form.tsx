"use client";

import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { createSubscriptionAction } from "@/app/(app)/admin/organizations/actions";
import type { listPlans } from "@/lib/billing/service";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

type PlanOption = Awaited<ReturnType<typeof listPlans>>[number];

export function CreateSubscriptionForm({
  organizationId,
  plans,
}: {
  organizationId: string;
  plans: PlanOption[];
}) {
  const [planId, setPlanId] = React.useState<string>(plans[0]?.id ?? "");
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () => createSubscriptionAction(organizationId, planId),
    onSuccess: () => {
      toast.success("Subscription added");
      queryClient.invalidateQueries({ queryKey: ["admin-organizations"] });
    },
    onError: () => toast.error("Failed to add subscription"),
  });

  if (plans.length === 0) {
    return <p className="text-sm text-muted-foreground">Create a plan in the catalog first.</p>;
  }

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (!planId) return;
        mutation.mutate();
      }}
      className="flex gap-2"
    >
      <Select value={planId} onValueChange={setPlanId}>
        <SelectTrigger className="flex-1">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {plans.map((p) => (
            <SelectItem key={p.id} value={p.id}>
              {p.name} — ${p.priceMonthly.toString()}/mo
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Button type="submit" disabled={mutation.isPending}>
        {mutation.isPending ? <Loader2 className="animate-spin" /> : <Plus />}
        Subscribe
      </Button>
    </form>
  );
}
