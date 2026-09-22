"use client";

import * as React from "react";
import { useMutation } from "@tanstack/react-query";
import { ShieldCheck, ShieldX, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { verifyAuditIntegrityAction } from "@/app/(app)/audit/actions";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

export function VerifyIntegrityButton() {
  const [result, setResult] = React.useState<boolean | null>(null);

  const mutation = useMutation({
    mutationFn: () => verifyAuditIntegrityAction(),
    onSuccess: (ok) => {
      setResult(ok);
      if (ok) toast.success("Hash chain verified — no tampering detected");
      else toast.error("Hash chain broken — possible tampering");
    },
  });

  return (
    <div className="flex items-center gap-3">
      <Button variant="outline" disabled={mutation.isPending} onClick={() => mutation.mutate()}>
        {mutation.isPending ? <Loader2 className="animate-spin" /> : <ShieldCheck />}
        Verify chain integrity
      </Button>
      {result !== null && (
        <Badge variant={result ? "secondary" : "destructive"} className="gap-1">
          {result ? <ShieldCheck className="size-3" /> : <ShieldX className="size-3" />}
          {result ? "Intact" : "Broken"}
        </Badge>
      )}
    </div>
  );
}
