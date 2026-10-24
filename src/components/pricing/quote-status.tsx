"use client";

import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Printer } from "lucide-react";
import { toast } from "sonner";

import { setQuoteStatusAction } from "@/app/(app)/pricing/actions";
import { Button } from "@/components/ui/button";
import { NativeSelect } from "@/components/ui/native-select";

export function QuoteStatusControl({ quoteId, status }: { quoteId: string; status: string }) {
  const router = useRouter();
  const mut = useMutation({
    mutationFn: (s: string) => setQuoteStatusAction(quoteId, s),
    onSuccess: () => {
      toast.success("Quote status updated");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  return (
    <div className="no-print flex items-center gap-2">
      <NativeSelect value={status} onChange={(e) => mut.mutate(e.target.value)} disabled={mut.isPending} aria-label="Quote status">
        <option value="DRAFT">Draft</option>
        <option value="SENT">Sent to client</option>
        <option value="ACCEPTED">Accepted</option>
        <option value="LOST">Lost</option>
      </NativeSelect>
      <Button variant="outline" size="sm" onClick={() => window.print()}>
        <Printer /> Print / PDF
      </Button>
    </div>
  );
}
