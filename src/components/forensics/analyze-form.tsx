"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, ScanSearch } from "lucide-react";
import { toast } from "sonner";

import { analyzeSubmissionAction } from "@/app/(app)/forensics/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { TenantSelect } from "@/components/shared/tenant-select";

export function AnalyzeForm({ tenants, defaultTenantId }: { tenants: Array<{ id: string; name: string }>; defaultTenantId: string | null }) {
  const router = useRouter();
  const [detonate, setDetonate] = React.useState(false);
  const [tenantId, setTenantId] = React.useState(defaultTenantId ?? "none");

  const done = (r: { caseId: string; verdict: string; score: number }) => {
    toast.success(`Verdict: ${r.verdict} (score ${r.score})`);
    router.push(`/cases/${r.caseId}`);
  };
  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Analysis failed");

  const analyze = useMutation({ mutationFn: (fd: FormData) => analyzeSubmissionAction(fd), onSuccess: done, onError });
  const busy = analyze.isPending;

  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        analyze.mutate(new FormData(e.currentTarget));
      }}
    >
      <div className="grid gap-1.5 sm:max-w-xs">
        <Label htmlFor="fx-tenant">Client</Label>
        <TenantSelect id="fx-tenant" tenants={tenants} value={tenantId} onChange={setTenantId} />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="fx-file">Email (.eml / Outlook .msg) or suspicious file</Label>
        <Input id="fx-file" name="file" type="file" />
        <p className="text-xs text-muted-foreground">
          .eml and .msg messages get header, body, attachment, and link analysis (embedded messages are opened one level deep). Any other file (Office, PDF, archive, executable, script, image) gets file forensics.
        </p>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="fx-raw">…or paste raw message source</Label>
        <Textarea id="fx-raw" name="raw" className="min-h-28 font-mono text-xs" aria-describedby="fx-raw-hint" />
        <p id="fx-raw-hint" className="text-xs text-muted-foreground">The full message source, headers included (in Outlook: File → Properties; in Gmail: Show original).</p>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="fx-archive-password">Archive password (optional)</Label>
        <Input id="fx-archive-password" name="archivePassword" type="password" autoComplete="off" aria-describedby="fx-archive-password-hint" />
        <p id="fx-archive-password-hint" className="text-xs text-muted-foreground">
          Opens password-protected ZIPs (ZipCrypto or AES). Passwords quoted in the message itself are tried automatically. The password isn&apos;t stored.
        </p>
      </div>
      <label className="flex items-start gap-2 text-sm">
        <Switch name="detonate" checked={detonate} onCheckedChange={setDetonate} className="mt-0.5" />
        <span>
          Detonate links (up to 5)
          <span className="block text-xs text-muted-foreground">
            Fetches each URL from this server over a guarded connection that refuses internal addresses, and inspects the landing page. JavaScript is not executed.
          </span>
        </span>
      </label>
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={busy}>
          {analyze.isPending ? <Loader2 className="animate-spin" /> : <ScanSearch />}
          Analyze
        </Button>
      </div>
    </form>
  );
}
