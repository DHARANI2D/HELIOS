"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, RotateCcw, Save } from "lucide-react";
import { toast } from "sonner";

import { resetPriceAction, savePriceAction } from "@/app/(app)/pricing/actions";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export interface PriceRow {
  key: string;
  group: string;
  label: string;
  unit: string;
  defaultPrice: number;
  defaultCost?: number;
  price: number;
  cost?: number;
  overridden: boolean;
  basis?: string;
}

function Row({ row, canEdit, showCost }: { row: PriceRow; canEdit: boolean; showCost: boolean }) {
  const router = useRouter();
  const [price, setPrice] = React.useState(String(row.price));
  const [cost, setCost] = React.useState(row.cost != null ? String(row.cost) : "");
  const dirty = Number(price) !== row.price || (cost === "" ? row.cost != null : Number(cost) !== row.cost);
  const save = useMutation({
    mutationFn: () => savePriceAction(row.key, Number(price), cost === "" ? null : Number(cost)),
    onSuccess: () => {
      toast.success(`${row.label} updated`);
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  const reset = useMutation({
    mutationFn: () => resetPriceAction(row.key),
    onSuccess: () => {
      setPrice(String(row.defaultPrice));
      setCost(row.defaultCost != null ? String(row.defaultCost) : "");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  return (
    <tr>
      <td className="py-1.5 pr-3">
        <p className="text-sm">{row.label}</p>
        <p className="text-[11px] text-muted-foreground">
          {row.unit}
          {row.basis === "estimate" && " · vendor estimate"}
          {row.overridden && <Badge variant="info" className="ml-1">custom</Badge>}
        </p>
      </td>
      <td className="px-2 py-1.5">
        <Input value={price} onChange={(e) => setPrice(e.target.value)} disabled={!canEdit} className="h-8 w-28 text-right tabular" inputMode="decimal" aria-label={`${row.label} price`} />
      </td>
      {showCost && (
        <td className="px-2 py-1.5">
          <Input value={cost} onChange={(e) => setCost(e.target.value)} disabled={!canEdit} placeholder="—" className="h-8 w-28 text-right tabular" inputMode="decimal" aria-label={`${row.label} cost`} />
        </td>
      )}
      <td className="py-1.5 text-right">
        {canEdit && (
          <div className="flex justify-end gap-1">
            {dirty && (
              <Button size="sm" className="h-7" onClick={() => save.mutate()} disabled={save.isPending}>
                {save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save
              </Button>
            )}
            {row.overridden && (
              <Button size="icon" variant="ghost" className="size-7" aria-label="Reset to default" onClick={() => reset.mutate()} disabled={reset.isPending}>
                <RotateCcw />
              </Button>
            )}
          </div>
        )}
      </td>
    </tr>
  );
}

export function PriceBookEditor({ rows, canEdit, showCost }: { rows: PriceRow[]; canEdit: boolean; showCost: boolean }) {
  const groups = [...new Set(rows.map((r) => r.group))];
  const [group, setGroup] = React.useState(groups[0]);
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-1.5">
        {groups.map((g) => (
          <button key={g} type="button" onClick={() => setGroup(g)} className={`rounded-full border px-3 py-1 text-xs font-medium hover:bg-accent ${group === g ? "border-primary bg-primary text-primary-foreground hover:bg-primary/90" : ""}`}>
            {g}
          </button>
        ))}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[32rem]">
          <thead>
            <tr className="border-b text-left text-xs text-muted-foreground">
              <th className="py-2 pr-3 font-medium">Item</th>
              <th className="px-2 py-2 font-medium">Sell price (USD)</th>
              {showCost && <th className="px-2 py-2 font-medium">Your cost (USD)</th>}
              <th />
            </tr>
          </thead>
          <tbody className="divide-y">
            {rows.filter((r) => r.group === group).map((r) => (
              <Row key={r.key} row={r} canEdit={canEdit} showCost={showCost} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
