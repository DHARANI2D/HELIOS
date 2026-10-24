"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Save } from "lucide-react";
import { toast } from "sonner";

import { savePriceAction } from "@/app/(app)/pricing/actions";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export interface PriceRow {
  key: string;
  group: string;
  label: string;
  unit: string;
  note?: string;
  hasCost: boolean;
  price: number | null;
  cost: number | null;
}

// "" → null (not set); anything else must be a number.
export function parseAmount(v: string): number | null | "invalid" {
  if (v.trim() === "") return null;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : "invalid";
}

const str = (n: number | null) => (n == null ? "" : String(n));

function Row({ row, canEdit, showCost }: { row: PriceRow; canEdit: boolean; showCost: boolean }) {
  const router = useRouter();
  const [price, setPrice] = React.useState(str(row.price));
  const [cost, setCost] = React.useState(str(row.cost));
  const p = parseAmount(price);
  const c = parseAmount(cost);
  const dirty = p !== row.price || (row.hasCost && c !== row.cost);
  const save = useMutation({
    mutationFn: () => {
      if (p === "invalid" || c === "invalid") throw new Error("Enter a number, or leave it empty");
      return savePriceAction(row.key, p, row.hasCost ? c : null);
    },
    onSuccess: () => {
      toast.success(`${row.label} saved`);
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  return (
    <tr>
      <td className="py-1.5 pr-3">
        <p className="text-sm">
          {row.label}
          {row.price == null && <Badge variant="warning" className="ml-1.5">not set</Badge>}
        </p>
        <p className="text-[11px] text-muted-foreground">{[row.unit, row.note].filter(Boolean).join(" · ")}</p>
      </td>
      <td className="px-2 py-1.5">
        <Input value={price} onChange={(e) => setPrice(e.target.value)} disabled={!canEdit} className="h-8 w-28 text-right tabular" inputMode="decimal" aria-label={`${row.label} price`} />
      </td>
      {showCost && (
        <td className="px-2 py-1.5">
          {row.hasCost ? <Input value={cost} onChange={(e) => setCost(e.target.value)} disabled={!canEdit} className="h-8 w-28 text-right tabular" inputMode="decimal" aria-label={`${row.label} cost`} /> : <span className="text-xs text-muted-foreground">n/a</span>}
        </td>
      )}
      <td className="py-1.5 text-right">
        {canEdit && dirty && (
          <Button size="sm" className="h-7" onClick={() => save.mutate()} disabled={save.isPending}>
            {save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save
          </Button>
        )}
      </td>
    </tr>
  );
}

export function PriceBookEditor({ rows, canEdit, showCost }: { rows: PriceRow[]; canEdit: boolean; showCost: boolean }) {
  const groups = [...new Set(rows.map((r) => r.group))];
  const [group, setGroup] = React.useState(groups[0]);
  const unset = rows.filter((r) => r.price == null).length;
  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-muted-foreground">
        Your own rates in USD. Nothing is pre-filled: {unset ? `${unset} of ${rows.length} items are not set yet. ` : "every item is set. "}
        A quote that needs an unset item shows it and can&apos;t be saved until it&apos;s filled in. Enter 0 for anything you don&apos;t charge.
      </p>
      <div className="flex flex-wrap gap-1.5">
        {groups.map((g) => {
          const missing = rows.filter((r) => r.group === g && r.price == null).length;
          return (
            <button key={g} type="button" onClick={() => setGroup(g)} className={`rounded-full border px-3 py-1 text-xs font-medium hover:bg-accent ${group === g ? "border-primary bg-primary text-primary-foreground hover:bg-primary/90" : ""}`}>
              {g}
              {missing > 0 && <span className="ml-1 opacity-70">· {missing}</span>}
            </button>
          );
        })}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[32rem]">
          <thead>
            <tr className="border-b text-left text-xs text-muted-foreground">
              <th className="py-2 pr-3 font-medium">Item</th>
              <th className="px-2 py-2 font-medium">Sell price</th>
              {showCost && <th className="px-2 py-2 font-medium">Your cost</th>}
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
