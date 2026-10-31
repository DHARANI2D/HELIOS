"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Check, Copy, Download, FileCheck2, Loader2, Server } from "lucide-react";
import { toast } from "sonner";

import { issueForwarderConfigAction, verifyForwarderConfigAction } from "@/app/(app)/integrations/actions";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";
import { unwrap } from "@/lib/action-result";

type Channel = "security" | "system" | "sysmon" | "powershell";

export interface ForwarderView {
  options: {
    os: "linux" | "windows";
    syslog: { udpPort: number | null; tcpPort: number | null; format: "rfc3164" | "rfc5424" } | null;
    windowsChannels: Channel[];
    files: string[];
    bufferLimitMb: number;
  } | null;
  currentHash: string | null;
  issuedAt: string | null;
  seen: { hash: string; at: string; status: "current" | "outdated" | "unknown" } | null;
}

const CHANNELS: Array<[Channel, string, string]> = [
  ["security", "Security", "Logons, process creation, account and group changes, log cleared"],
  ["system", "System", "Services installed, System log cleared"],
  ["sysmon", "Sysmon", "Processes, network connections, file creation, DNS (needs Sysmon installed)"],
  ["powershell", "PowerShell script blocks", "What PowerShell ran (needs script block logging on)"],
];

const SEEN: Record<"current" | "outdated" | "unknown", { label: string; variant: "success" | "warning" | "destructive" }> = {
  current: { label: "running the current configuration", variant: "success" },
  outdated: { label: "running an older configuration", variant: "warning" },
  unknown: { label: "running a configuration HELIOS didn't issue", variant: "destructive" },
};

export function ForwarderButton({ integrationId, name, view, canManage }: { integrationId: string; name: string; view: ForwarderView; canManage: boolean }) {
  const router = useRouter();
  const o = view.options;
  const [open, setOpen] = React.useState(false);
  const [os, setOs] = React.useState<"linux" | "windows">(o?.os ?? "linux");
  const [syslogOn, setSyslogOn] = React.useState(o ? !!o.syslog : true);
  const [udp, setUdp] = React.useState(String(o?.syslog?.udpPort ?? 514));
  const [tcp, setTcp] = React.useState(o?.syslog?.tcpPort ? String(o.syslog.tcpPort) : "");
  const [format, setFormat] = React.useState<"rfc3164" | "rfc5424">(o?.syslog?.format ?? "rfc3164");
  const [channels, setChannels] = React.useState<Channel[]>(o?.windowsChannels ?? ["security", "system"]);
  const [files, setFiles] = React.useState((o?.files ?? []).join("\n"));
  const [buffer, setBuffer] = React.useState(String(o?.bufferLimitMb ?? 2048));
  const [issued, setIssued] = React.useState<{ text: string; hash: string } | null>(null);
  const [check, setCheck] = React.useState("");
  const [copied, setCopied] = React.useState(false);
  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed");

  const port = (v: string) => (v.trim() ? Number(v) : null);
  const issue = useMutation({
    mutationFn: () =>
      unwrap(issueForwarderConfigAction(integrationId, {
        os,
        syslog: syslogOn ? { udpPort: port(udp), tcpPort: port(tcp), format } : null,
        windowsChannels: os === "windows" ? channels : [],
        files: files.split("\n").map((f) => f.trim()).filter(Boolean),
        bufferLimitMb: Number(buffer) || 2048,
      })),
    onSuccess: (r) => {
      setIssued(r);
      toast.success("Configuration issued: deploy it to the forwarder");
      router.refresh();
    },
    onError,
  });
  const verify = useMutation({
    mutationFn: () => unwrap(verifyForwarderConfigAction(check)),
    onSuccess: (r) => (r.ok ? toast.success : toast.error)(r.reason),
    onError,
  });

  const download = () => {
    if (!issued) return;
    const url = URL.createObjectURL(new Blob([issued.text], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "helios-forwarder.conf";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <Button size="sm" variant="ghost" className="h-7" onClick={() => setOpen(true)}>
        <Server /> Forwarder
        {view.seen && view.seen.status !== "current" && <span className="size-1.5 rounded-full bg-destructive" aria-label="configuration drift" />}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{name}: forwarder</DialogTitle>
            <DialogDescription>
              A stock Fluent Bit (3.x or later) with a configuration HELIOS signs. It buffers to disk, so an outage loses nothing, and sends gzip over HTTPS with this
              integration&apos;s ingest token.
            </DialogDescription>
          </DialogHeader>

          {view.seen ? (
            <p className="text-sm">
              <Badge variant={SEEN[view.seen.status].variant}>{SEEN[view.seen.status].label}</Badge>{" "}
              <span className="text-xs text-muted-foreground">last reported {new Date(view.seen.at).toLocaleString()} · {view.seen.hash.slice(0, 12)}</span>
            </p>
          ) : view.currentHash ? (
            <p className="text-xs text-muted-foreground">Issued {view.issuedAt ? new Date(view.issuedAt).toLocaleString() : ""} ({view.currentHash.slice(0, 12)}); no forwarder has reported yet.</p>
          ) : null}

          {canManage && (
            <div className="grid gap-3">
              <div className="grid grid-cols-2 gap-3">
                <div className="grid gap-1.5">
                  <Label htmlFor="fw-os">Runs on</Label>
                  <NativeSelect id="fw-os" value={os} onChange={(e) => setOs(e.target.value as "linux" | "windows")}>
                    <option value="linux">Linux (a small VM or appliance)</option>
                    <option value="windows">Windows (a server or each host)</option>
                  </NativeSelect>
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="fw-buf">Disk buffer (MB)</Label>
                  <Input id="fw-buf" inputMode="numeric" value={buffer} onChange={(e) => setBuffer(e.target.value)} />
                </div>
              </div>

              <fieldset className="grid gap-2 rounded-md border p-3">
                <label className="flex items-center gap-2 text-sm font-medium">
                  <input type="checkbox" checked={syslogOn} onChange={(e) => setSyslogOn(e.target.checked)} /> Syslog from firewalls, switches and Linux servers
                </label>
                {syslogOn && (
                  <div className="grid grid-cols-3 gap-2">
                    <div className="grid gap-1">
                      <Label htmlFor="fw-udp" className="text-xs">UDP port</Label>
                      <Input id="fw-udp" inputMode="numeric" value={udp} onChange={(e) => setUdp(e.target.value)} placeholder="514" />
                    </div>
                    <div className="grid gap-1">
                      <Label htmlFor="fw-tcp" className="text-xs">TCP port</Label>
                      <Input id="fw-tcp" inputMode="numeric" value={tcp} onChange={(e) => setTcp(e.target.value)} placeholder="none" />
                    </div>
                    <div className="grid gap-1">
                      <Label htmlFor="fw-fmt" className="text-xs">Format</Label>
                      <NativeSelect id="fw-fmt" value={format} onChange={(e) => setFormat(e.target.value as "rfc3164" | "rfc5424")}>
                        <option value="rfc3164">RFC 3164 (BSD)</option>
                        <option value="rfc5424">RFC 5424</option>
                      </NativeSelect>
                    </div>
                  </div>
                )}
                <p className="text-[11px] text-muted-foreground">Read: FortiGate and other key=value logs, CEF (Palo Alto, Check Point and others), OPNsense and pfSense filterlog, OpenSSH sign-ins.</p>
              </fieldset>

              {os === "windows" && (
                <fieldset className="grid gap-2 rounded-md border p-3">
                  <legend className="px-1 text-sm font-medium">Windows event logs</legend>
                  {CHANNELS.map(([key, label, what]) => (
                    <label key={key} className="flex items-start gap-2 text-sm">
                      <input type="checkbox" className="mt-1" checked={channels.includes(key)} onChange={(e) => setChannels(e.target.checked ? [...channels, key] : channels.filter((c) => c !== key))} />
                      <span>{label}<span className="block text-[11px] text-muted-foreground">{what}</span></span>
                    </label>
                  ))}
                </fieldset>
              )}

              <div className="grid gap-1.5">
                <Label htmlFor="fw-files">Log files to tail (one path or pattern per line, optional)</Label>
                <Textarea id="fw-files" rows={2} className="font-mono text-xs" value={files} onChange={(e) => setFiles(e.target.value)} placeholder={os === "windows" ? "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*.log" : "/var/log/auth.log"} />
              </div>
            </div>
          )}

          {issued && (
            <div className="grid gap-2">
              <div className="flex items-center justify-between">
                <p className="text-sm font-medium">helios-forwarder.conf <span className="font-mono text-xs text-muted-foreground">{issued.hash.slice(0, 12)}</span></p>
                <div className="flex gap-1">
                  <Button size="sm" variant="outline" onClick={() => navigator.clipboard.writeText(issued.text).then(() => setCopied(true))}>{copied ? <Check /> : <Copy />} Copy</Button>
                  <Button size="sm" variant="outline" onClick={download}><Download /> Download</Button>
                </div>
              </div>
              <pre className="max-h-64 overflow-auto rounded-md border bg-muted/40 p-3 text-[11px] leading-relaxed">{issued.text}</pre>
              <ol className="list-decimal space-y-1 pl-5 text-xs text-muted-foreground">
                <li>Install Fluent Bit 3.x or later from fluentbit.io on the {os === "windows" ? "Windows server" : "Linux host"}.</li>
                <li>Save this file as its configuration{os === "windows" ? " (C:\\Program Files\\fluent-bit\\conf\\fluent-bit.conf)" : " (/etc/fluent-bit/fluent-bit.conf)"}, next to Fluent Bit&apos;s own parsers.conf.</li>
                <li>Set HELIOS_INGEST_TOKEN in the service&apos;s environment to the ingest token from onboarding (rotate it from Manage if you no longer have it).</li>
                <li>Point the firewalls&apos; syslog at this host and restart Fluent Bit. The first events show up in Log sources within a minute.</li>
              </ol>
            </div>
          )}

          <details className="rounded-md border p-3">
            <summary className="cursor-pointer text-sm font-medium">Check a configuration file</summary>
            <p className="mt-1 text-[11px] text-muted-foreground">Paste the file from a forwarder to see whether HELIOS issued it and whether it has been changed since.</p>
            <Textarea rows={4} className="mt-2 font-mono text-[11px]" value={check} onChange={(e) => setCheck(e.target.value)} aria-label="Configuration to check" />
            <Button size="sm" variant="outline" className="mt-2" onClick={() => verify.mutate()} disabled={!check.trim() || verify.isPending}>
              {verify.isPending ? <Loader2 className="animate-spin" /> : <FileCheck2 />} Check
            </Button>
          </details>

          {canManage && (
            <DialogFooter>
              <Button onClick={() => issue.mutate()} disabled={issue.isPending}>
                {issue.isPending ? <Loader2 className="animate-spin" /> : <Server />} {view.currentHash ? "Issue a new configuration" : "Issue configuration"}
              </Button>
            </DialogFooter>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}
