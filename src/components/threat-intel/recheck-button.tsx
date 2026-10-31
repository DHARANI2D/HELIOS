"use client";

import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, RefreshCw } from "lucide-react";
import { toast } from "sonner";

import { recheckIndicatorAction } from "@/app/(app)/threat-intel/actions";
import { Button } from "@/components/ui/button";
import { unwrap } from "@/lib/action-result";

export function RecheckButton({ indicatorId }: { indicatorId: string }) {
  const router = useRouter();
  const recheck = useMutation({
    mutationFn: () => unwrap(recheckIndicatorAction(indicatorId)),
    onSuccess: (r) => {
      if (r.providersConfigured.length === 0) {
        toast.info("No threat-intel providers configured — showing built-in intel only. Add a VirusTotal or AbuseIPDB key under Settings.");
      } else if (r.errors.length) {
        toast.warning(`Lookup finished with errors: ${r.errors.map((e) => `${e.provider} (${e.error})`).join(", ")}`);
      } else {
        toast.success(`${r.value}: ${r.verdict}`);
      }
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Lookup failed"),
  });
  return (
    <Button size="icon" variant="ghost" className="size-7" onClick={() => recheck.mutate()} disabled={recheck.isPending} aria-label="Re-check with providers">
      {recheck.isPending ? <Loader2 className="size-3.5 animate-spin" /> : <RefreshCw className="size-3.5" />}
    </Button>
  );
}
