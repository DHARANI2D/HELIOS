"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { listPlansAction, togglePlanActiveAction } from "@/app/(app)/admin/plans/actions";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Switch } from "@/components/ui/switch";

type PlanRow = Awaited<ReturnType<typeof listPlansAction>>[number];

export function PlansTable({ initialData }: { initialData: PlanRow[] }) {
  const queryClient = useQueryClient();
  const { data } = useQuery({
    queryKey: ["admin-plans"],
    queryFn: () => listPlansAction(),
    initialData,
  });

  const toggle = useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) => togglePlanActiveAction(id, active),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin-plans"] }),
  });

  if (!data.length) {
    return (
      <p className="py-10 text-center text-sm text-muted-foreground">
        No plans yet — create one above.
      </p>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Name</TableHead>
          <TableHead>Service</TableHead>
          <TableHead>AI tier</TableHead>
          <TableHead>Price / mo</TableHead>
          <TableHead>Active</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.map((plan) => (
          <TableRow key={plan.id}>
            <TableCell className="font-medium">{plan.name}</TableCell>
            <TableCell>{plan.serviceType.replaceAll("_", " ")}</TableCell>
            <TableCell>{plan.aiTier}</TableCell>
            <TableCell>${plan.priceMonthly.toString()}</TableCell>
            <TableCell>
              <Switch
                checked={plan.active}
                onCheckedChange={(checked) => toggle.mutate({ id: plan.id, active: checked })}
              />
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
