"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Check, Copy, KeyRound, Loader2, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { createApiTokenAction, revokeApiTokenAction } from "@/app/(app)/api-tokens/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";

export function CreateTokenForm({ canWriteAnything }: { canWriteAnything: boolean }) {
  const router = useRouter();
  const [name, setName] = React.useState("");
  const [canWrite, setCanWrite] = React.useState(false);
  const [expires, setExpires] = React.useState("90");
  const [issued, setIssued] = React.useState<string | null>(null);
  const [copied, setCopied] = React.useState(false);
  const create = useMutation({
    mutationFn: () => createApiTokenAction({ name, canWrite, expiresInDays: expires === "never" ? null : (Number(expires) as 30 | 90 | 365) }),
    onSuccess: ({ token }) => {
      setIssued(token);
      setName("");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });

  if (issued) {
    return (
      <div className="flex flex-col gap-3 rounded-lg border border-warning/50 bg-warning/10 p-4">
        <p className="flex items-center gap-2 text-sm font-medium"><KeyRound className="size-4" /> Copy this token now — it won&apos;t be shown again</p>
        <div className="flex gap-2">
          <Input readOnly value={issued} className="font-mono text-xs" aria-label="New API token" onFocus={(e) => e.currentTarget.select()} />
          <Button
            variant="outline"
            onClick={() => {
              void navigator.clipboard.writeText(issued).then(() => setCopied(true));
            }}
          >
            {copied ? <Check /> : <Copy />} {copied ? "Copied" : "Copy"}
          </Button>
        </div>
        <div>
          <Button size="sm" variant="ghost" onClick={() => { setIssued(null); setCopied(false); }}>Done</Button>
        </div>
      </div>
    );
  }

  return (
    <form
      className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto_auto_auto] sm:items-end"
      onSubmit={(e) => {
        e.preventDefault();
        create.mutate();
      }}
    >
      <div className="grid gap-1.5">
        <Label htmlFor="token-name">Name</Label>
        <Input id="token-name" value={name} onChange={(e) => setName(e.target.value)} aria-describedby="token-name-hint" />
        <p id="token-name-hint" className="text-[11px] text-muted-foreground">What will use it, e.g. the ticketing integration.</p>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="token-expiry">Expires</Label>
        <NativeSelect id="token-expiry" value={expires} onChange={(e) => setExpires(e.target.value)}>
          <option value="30">in 30 days</option>
          <option value="90">in 90 days</option>
          <option value="365">in a year</option>
          <option value="never">never</option>
        </NativeSelect>
      </div>
      <label className="flex h-9 items-center gap-2 text-sm">
        <Switch checked={canWrite} onCheckedChange={setCanWrite} disabled={!canWriteAnything} />
        Read &amp; write
      </label>
      <Button type="submit" disabled={create.isPending || name.trim().length < 2}>
        {create.isPending ? <Loader2 className="animate-spin" /> : <Plus />}
        Create token
      </Button>
    </form>
  );
}

export function RevokeTokenButton({ tokenId, name }: { tokenId: string; name: string }) {
  const router = useRouter();
  const revoke = useMutation({
    mutationFn: () => revokeApiTokenAction(tokenId),
    onSuccess: () => {
      toast.success(`Revoked "${name}"`);
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  return (
    <Button size="sm" variant="ghost" onClick={() => revoke.mutate()} disabled={revoke.isPending} aria-label={`Revoke ${name}`}>
      {revoke.isPending ? <Loader2 className="animate-spin" /> : <Trash2 />} Revoke
    </Button>
  );
}
