"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Search } from "lucide-react";
import { toast } from "sonner";

import { startInvestigationAction } from "@/app/(app)/investigations/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { TenantSelect } from "@/components/shared/tenant-select";

export function NewInvestigationForm({ tenants, defaultTenantId }: { tenants: Array<{ id: string; name: string }>; defaultTenantId: string | null }) {
  const router = useRouter();
  const formRef = React.useRef<HTMLFormElement>(null);
  const [title, setTitle] = React.useState("");
  const [details, setDetails] = React.useState("");
  const [logs, setLogs] = React.useState("");

  const start = useMutation({
    mutationFn: (fd: FormData) => startInvestigationAction(fd),
    onSuccess: (r) => {
      toast.success(`Investigation started on ${r.eventCount} events${r.skipped.length ? ` (skipped: ${r.skipped.join("; ")})` : ""}`);
      router.push(`/cases/${r.caseId}`);
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Could not start investigation"),
  });

  return (
    <form
      ref={formRef}
      className="flex flex-col gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        start.mutate(new FormData(e.currentTarget));
      }}
    >
      <div className="grid gap-3 sm:grid-cols-[1fr_14rem]">
        <div className="grid gap-1.5">
          <Label htmlFor="inv-title">Title</Label>
          <Input id="inv-title" name="title" value={title} onChange={(e) => setTitle(e.target.value)} required />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="inv-tenant">Client</Label>
          <TenantSelect id="inv-tenant" tenants={tenants} defaultValue={defaultTenantId} />
        </div>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="inv-details">Alert details</Label>
        <Textarea id="inv-details" name="alertDetails" value={details} onChange={(e) => setDetails(e.target.value)} className="min-h-20" aria-describedby="inv-details-hint" />
        <p id="inv-details-hint" className="text-xs text-muted-foreground">The originating alert, ticket notes, or your hypothesis.</p>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="inv-files">Telemetry files</Label>
        <Input id="inv-files" name="files" type="file" multiple accept=".evtx,.xlsx,.json,.jsonl,.ndjson,.csv,.tsv,.xml,.log,.txt,.zip" />
        <p className="text-xs text-muted-foreground">
          Windows event logs (.evtx straight from Event Viewer, or exported XML/JSON — Security, System, PowerShell, Sysmon), CrowdStrike, Wazuh, Google SecOps UDM, search exports as CSV or Excel (.xlsx), generic JSON/JSONL, or plain logs. ZIPs are expanded, password-protected ones too. Up to 25 MB per upload.
        </p>
      </div>
      <div className="grid gap-1.5 sm:max-w-sm">
        <Label htmlFor="inv-archive-password">Archive password (optional)</Label>
        <Input id="inv-archive-password" name="archivePassword" type="password" autoComplete="off" aria-describedby="inv-archive-password-hint" />
        <p id="inv-archive-password-hint" className="text-xs text-muted-foreground">For a password-protected ZIP (ZipCrypto or AES). Used to open it, never stored.</p>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="inv-logs">…or paste logs</Label>
        <Textarea id="inv-logs" name="pastedLogs" value={logs} onChange={(e) => setLogs(e.target.value)} className="min-h-28 font-mono text-xs" />
      </div>
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={start.isPending}>
          {start.isPending ? <Loader2 className="animate-spin" /> : <Search />}
          Start investigation
        </Button>
      </div>
    </form>
  );
}
