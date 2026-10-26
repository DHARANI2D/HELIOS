"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { KeySquare, Loader2, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { destroyTenantKeysAction, rotateTenantKeyAction } from "@/app/(app)/tenants/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export function TenantKeys({ tenantId, name, version, createdAt, destroyed, suspended }: { tenantId: string; name: string; version: number | null; createdAt: string | null; destroyed: boolean; suspended: boolean }) {
  const router = useRouter();
  const [confirm, setConfirm] = React.useState("");
  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed");
  const rotate = useMutation({ mutationFn: () => rotateTenantKeyAction(tenantId), onSuccess: (r) => { toast.success(`New key; ${r.resealed} credential${r.resealed === 1 ? "" : "s"} re-sealed`); router.refresh(); }, onError });
  const destroy = useMutation({ mutationFn: () => destroyTenantKeysAction(tenantId, confirm), onSuccess: () => { toast.success("Keys destroyed: the client's stored credentials can't be read"); router.refresh(); }, onError });
  if (destroyed) return <p className="text-sm text-muted-foreground">Destroyed: this client&apos;s stored credentials can no longer be decrypted.</p>;
  return (
    <div className="grid gap-3 text-sm">
      <p className="text-muted-foreground">{version ? `Data key version ${version}, created ${createdAt ? new Date(createdAt).toLocaleDateString() : "—"}.` : "No key yet: one is made the first time a credential of this client is stored."}</p>
      <Button size="sm" variant="outline" className="w-fit" onClick={() => rotate.mutate()} disabled={rotate.isPending}>{rotate.isPending ? <Loader2 className="animate-spin" /> : <KeySquare />} Rotate key</Button>
      {suspended && (
        <div className="grid gap-1.5 rounded-md border border-destructive/40 p-2">
          <p className="text-xs">Offboarding: destroy the keys so this client&apos;s credentials can&apos;t be decrypted, here or from a backup. Type <strong>{name}</strong> to confirm.</p>
          <Input value={confirm} onChange={(e) => setConfirm(e.target.value)} aria-label="Client name to confirm" />
          <Button size="sm" variant="destructive" className="w-fit" onClick={() => destroy.mutate()} disabled={confirm !== name || destroy.isPending}>{destroy.isPending ? <Loader2 className="animate-spin" /> : <Trash2 />} Destroy keys</Button>
        </div>
      )}
    </div>
  );
}
