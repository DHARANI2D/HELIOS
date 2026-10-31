"use client";

import * as React from "react";
import { useMutation } from "@tanstack/react-query";
import { ShieldCheck, ShieldAlert, Loader2 } from "lucide-react";

import { verifyAuditChainAction } from "@/app/(app)/audit/actions";
import { Button } from "@/components/ui/button";
import { unwrap } from "@/lib/action-result";

export function VerifyChainButton() {
  const verify = useMutation({ mutationFn: () => unwrap(verifyAuditChainAction()) });
  const result = verify.data;

  return (
    <div className="flex flex-wrap items-center gap-3">
      <Button variant="outline" size="sm" onClick={() => verify.mutate()} disabled={verify.isPending}>
        {verify.isPending ? <Loader2 className="animate-spin" /> : <ShieldCheck />}
        Verify chain integrity
      </Button>
      {result && result.valid && (
        <span className="flex items-center gap-1.5 text-xs text-success-ink">
          <ShieldCheck className="size-3.5" />
          All {result.checked} entries verified — chain intact
        </span>
      )}
      {result && !result.valid && result.brokenAt && (
        <span className="flex items-center gap-1.5 text-xs text-destructive">
          <ShieldAlert className="size-3.5" />
          Chain broken at entry #{result.brokenAt.seq} (
          {result.brokenAt.reason === "hash_mismatch" ? "content altered" : "link to previous entry altered"})
        </span>
      )}
      {verify.isError && <span className="text-xs text-destructive">Verification failed to run</span>}
    </div>
  );
}
