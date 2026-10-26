"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Check, Clock, Download, FilePlus2, Loader2, Pencil, RotateCcw, Send, ShieldCheck, X } from "lucide-react";
import { toast } from "sonner";

import {
  addUpdateAction,
  approveNoticeAction,
  extendDeadlineAction,
  notRequiredAction,
  openCertInAction,
  openDpdpAction,
  reopenNoticeAction,
  requestApprovalAction,
  saveNoticeAction,
  setClockStartAction,
  submitNoticeAction,
} from "@/app/(app)/compliance/actions";
import { clockOf, formatSpan, SUBMIT_CHANNELS, type ClockState } from "@/lib/compliance/notices";
import { formatDateTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";

export interface NoticeView {
  id: string;
  kind: "CERT_IN" | "DPDP_INTIMATION" | "DPDP_REPORT" | "DPDP_PRINCIPALS";
  label: string;
  recipient: string;
  deadline: string;
  sequence: number;
  status: "DRAFT" | "AWAITING_APPROVAL" | "APPROVED" | "SUBMITTED" | "NOT_REQUIRED";
  clockStartAt: string;
  dueAt: string | null;
  categories: string[];
  content: Record<string, unknown>;
  missing: string[];
  proposedBy: string;
  approvedByName: string | null;
  approvedVia: string | null;
  approvedAt: string | null;
  submittedAt: string | null;
  submittedVia: string | null;
  reference: string | null;
  recipientsCount: number | null;
  notRequiredReason: string | null;
  latest: boolean;
}

export interface CaseNoticesProps {
  caseId: string;
  now: string;
  createdAt: string;
  obligations: { certIn: boolean; dpdp: boolean; minSeverity: string; withoutDelayHours: number } | null;
  matches: Array<{ code: string; label: string; reasons: string[] }>;
  categories: Array<{ code: string; label: string }>;
  notices: NoticeView[];
  mail: { configured: boolean; reason?: string };
  perms: { prepare: boolean; approve: boolean; isClient: boolean };
  dpdpInForce: boolean;
}

const STATUS_LABEL: Record<NoticeView["status"], string> = {
  DRAFT: "Draft",
  AWAITING_APPROVAL: "With the client",
  APPROVED: "Approved",
  SUBMITTED: "Filed",
  NOT_REQUIRED: "Not required",
};
const STATUS_VARIANT = { DRAFT: "outline", AWAITING_APPROVAL: "warning", APPROVED: "soft", SUBMITTED: "success", NOT_REQUIRED: "secondary" } as const;
const CLOCK_TONE: Record<ClockState, string> = {
  running: "text-info-ink",
  due_soon: "text-warning-ink",
  overdue: "text-destructive",
  met: "text-success-ink",
  late: "text-destructive",
  closed: "text-muted-foreground",
};

const onError = (e: Error) => toast.error(e.message);
const localInput = (iso: string) => {
  const d = new Date(iso);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
};
const fromLocal = (v: string) => new Date(v).toISOString();

function useTicking(initial: string) {
  const [now, setNow] = React.useState(() => new Date(initial));
  React.useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 30_000);
    return () => clearInterval(t);
  }, []);
  return now;
}

function ClockChip({ n, now }: { n: NoticeView; now: Date }) {
  const c = clockOf({ clockStartAt: new Date(n.clockStartAt), dueAt: n.dueAt ? new Date(n.dueAt) : null, submittedAt: n.submittedAt ? new Date(n.submittedAt) : null, status: n.status }, now);
  const text =
    c.state === "closed" ? "No deadline"
      : c.state === "met" ? (c.marginMs != null ? `Filed ${formatSpan(c.elapsedMs)} after the clock started, ${formatSpan(c.marginMs)} early` : "Filed")
        : c.state === "late" ? `Filed ${formatSpan(-(c.marginMs ?? 0))} late`
          : c.state === "overdue" ? `Overdue by ${formatSpan(-(c.marginMs ?? 0))}`
            : c.marginMs != null ? `${formatSpan(c.marginMs)} left` : "No fixed deadline";
  return (
    <span className={cn("inline-flex items-center gap-1 text-xs font-medium tabular", CLOCK_TONE[c.state])}>
      <Clock className="size-3.5" /> {text}
    </span>
  );
}

// ---------------------------------------------------------------- content editor

type Field = { path: string[]; label: string; type: "text" | "textarea" | "lines" | "number" | "datetime" | "list" | "bool" };

const FIELDS: Record<NoticeView["kind"], Field[]> = {
  CERT_IN: [
    { path: ["reporter", "name"], label: "Point of contact", type: "text" },
    { path: ["reporter", "designation"], label: "Designation", type: "text" },
    { path: ["reporter", "organisation"], label: "Organisation", type: "text" },
    { path: ["reporter", "email"], label: "Contact email", type: "text" },
    { path: ["reporter", "phone"], label: "Contact phone", type: "text" },
    { path: ["reporter", "address"], label: "Address", type: "text" },
    { path: ["sector"], label: "Sector", type: "text" },
    { path: ["occurredAt"], label: "When it occurred", type: "datetime" },
    { path: ["description"], label: "Description", type: "textarea" },
    { path: ["symptoms"], label: "Symptoms observed (one per line)", type: "lines" },
    { path: ["actionsTaken"], label: "Actions taken (one per line)", type: "lines" },
    { path: ["techniques"], label: "Techniques (one per line)", type: "lines" },
    { path: ["criticalSystems"], label: "Critical systems affected", type: "bool" },
    { path: ["reportedTo"], label: "Also reported to (sector regulator, police, …)", type: "text" },
    { path: ["additionalInfo"], label: "Additional information", type: "textarea" },
  ],
  DPDP_INTIMATION: [
    { path: ["nature"], label: "Nature of the breach", type: "textarea" },
    { path: ["extent"], label: "Extent", type: "textarea" },
    { path: ["principalsAffected"], label: "People affected (estimate)", type: "number" },
    { path: ["dataCategories"], label: "Personal data involved (comma-separated)", type: "list" },
    { path: ["occurredAt"], label: "When it happened", type: "datetime" },
    { path: ["location"], label: "Where it happened", type: "text" },
    { path: ["likelyImpact"], label: "Likely impact", type: "textarea" },
  ],
  DPDP_REPORT: [
    { path: ["facts"], label: "Facts, circumstances and reasons", type: "textarea" },
    { path: ["mitigation"], label: "Measures taken or proposed to mitigate the risk", type: "textarea" },
    { path: ["personFindings"], label: "Findings about the person who caused it", type: "textarea" },
    { path: ["remediation"], label: "Measures to prevent it happening again", type: "textarea" },
    { path: ["principalsReport"], label: "Report on telling the people affected (blank: filled from that notice)", type: "textarea" },
  ],
  DPDP_PRINCIPALS: [
    { path: ["description"], label: "What happened: nature, extent, when and where", type: "textarea" },
    { path: ["consequences"], label: "What it could mean for them", type: "textarea" },
    { path: ["mitigation"], label: "What has been done", type: "textarea" },
    { path: ["safetySteps"], label: "What they can do to protect themselves", type: "textarea" },
    { path: ["contact", "name"], label: "Contact name", type: "text" },
    { path: ["contact", "email"], label: "Contact email", type: "text" },
    { path: ["contact", "phone"], label: "Contact phone", type: "text" },
  ],
};

const getAt = (obj: Record<string, unknown>, path: string[]): unknown => path.reduce<unknown>((o, k) => (o && typeof o === "object" ? (o as Record<string, unknown>)[k] : undefined), obj);
function setAt(obj: Record<string, unknown>, path: string[], value: unknown): Record<string, unknown> {
  const [head, ...rest] = path;
  if (!rest.length) return { ...obj, [head]: value };
  return { ...obj, [head]: setAt((obj[head] as Record<string, unknown>) ?? {}, rest, value) };
}

interface SystemRow { hostname: string; ip: string; os: string; type: string; critical: boolean }

function NoticeEditor({ n, categories, onClose }: { n: NoticeView; categories: CaseNoticesProps["categories"]; onClose: () => void }) {
  const router = useRouter();
  const [content, setContent] = React.useState<Record<string, unknown>>(n.content);
  const [cats, setCats] = React.useState<string[]>(n.categories);
  const save = useMutation({
    mutationFn: () => saveNoticeAction(n.id, { content, categories: n.kind === "CERT_IN" ? cats : undefined }),
    onSuccess: () => {
      toast.success(n.status === "DRAFT" ? "Saved" : "Saved; it goes back to the client for approval");
      onClose();
      router.refresh();
    },
    onError,
  });
  const systems = (content.affectedSystems as SystemRow[] | undefined) ?? [];
  const setSystems = (rows: SystemRow[]) => setContent((c) => ({ ...c, affectedSystems: rows }));

  return (
    <div className="flex max-h-[65vh] flex-col gap-3 overflow-y-auto pr-1">
      {n.kind === "CERT_IN" && (
        <fieldset className="grid gap-1">
          <legend className="text-xs font-medium">Incident type (CERT-In Annexure I)</legend>
          {categories.map((c) => (
            <label key={c.code} className="flex items-start gap-2 text-xs">
              <input type="checkbox" className="mt-0.5" checked={cats.includes(c.code)} onChange={(e) => setCats(e.target.checked ? [...cats, c.code] : cats.filter((x) => x !== c.code))} />
              <span><span className="font-mono">({c.code})</span> {c.label}</span>
            </label>
          ))}
        </fieldset>
      )}
      <div className="grid gap-3 sm:grid-cols-2">
        {FIELDS[n.kind].map((f) => {
          const id = `${n.id}-${f.path.join("-")}`;
          const v = getAt(content, f.path);
          const set = (value: unknown) => setContent((c) => setAt(c, f.path, value));
          const wide = f.type === "textarea" || f.type === "lines";
          return (
            <div key={id} className={cn("grid gap-1.5", wide && "sm:col-span-2")}>
              {f.type === "bool" ? (
                <label className="flex items-center gap-2 text-xs"><input id={id} type="checkbox" checked={!!v} onChange={(e) => set(e.target.checked)} /> {f.label}</label>
              ) : (
                <>
                  <Label htmlFor={id} className="text-xs">{f.label}</Label>
                  {f.type === "textarea" ? (
                    <Textarea id={id} rows={4} className="text-xs" value={String(v ?? "")} onChange={(e) => set(e.target.value)} />
                  ) : f.type === "lines" ? (
                    <Textarea id={id} rows={4} className="font-mono text-xs" value={((v as string[]) ?? []).join("\n")} onChange={(e) => set(e.target.value.split("\n").map((l) => l.trim()).filter(Boolean))} />
                  ) : f.type === "list" ? (
                    <Input id={id} className="h-8 text-xs" defaultValue={((v as string[]) ?? []).join(", ")} onBlur={(e) => set(e.target.value.split(",").map((l) => l.trim()).filter(Boolean))} />
                  ) : f.type === "number" ? (
                    <Input id={id} type="number" min={0} className="h-8 text-xs" value={v == null ? "" : String(v)} onChange={(e) => set(e.target.value === "" ? null : Math.max(0, Math.round(Number(e.target.value))))} />
                  ) : f.type === "datetime" ? (
                    <Input id={id} type="datetime-local" className="h-8 text-xs" value={typeof v === "string" && v ? localInput(v) : ""} onChange={(e) => set(e.target.value ? fromLocal(e.target.value) : null)} />
                  ) : (
                    <Input id={id} className="h-8 text-xs" value={String(v ?? "")} onChange={(e) => set(e.target.value)} />
                  )}
                </>
              )}
            </div>
          );
        })}
      </div>
      {n.kind === "CERT_IN" && (
        <div className="grid gap-1.5">
          <p className="text-xs font-medium">Affected systems</p>
          {systems.map((s, i) => (
            <div key={i} className="grid grid-cols-[1fr_1fr_1fr_1fr_auto_auto] items-center gap-1.5">
              {(["hostname", "ip", "os", "type"] as const).map((k) => (
                <Input key={k} aria-label={k} placeholder={k === "ip" ? "IP address" : k === "os" ? "Operating system" : k} className="h-7 text-xs" value={s[k]} onChange={(e) => setSystems(systems.map((r, j) => (j === i ? { ...r, [k]: e.target.value } : r)))} />
              ))}
              <label className="flex items-center gap-1 text-[11px]"><input type="checkbox" checked={s.critical} onChange={(e) => setSystems(systems.map((r, j) => (j === i ? { ...r, critical: e.target.checked } : r)))} /> critical</label>
              <Button type="button" size="icon" variant="ghost" className="size-7" aria-label="Remove" onClick={() => setSystems(systems.filter((_, j) => j !== i))}><X /></Button>
            </div>
          ))}
          <Button type="button" variant="outline" size="sm" className="w-fit" onClick={() => setSystems([...systems, { hostname: "", ip: "", os: "", type: "", critical: false }])}>Add a system</Button>
        </div>
      )}
      <DialogFooter>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button onClick={() => save.mutate()} disabled={save.isPending}>{save.isPending && <Loader2 className="animate-spin" />} Save</Button>
      </DialogFooter>
    </div>
  );
}

// ---------------------------------------------------------------- dialogs

type Dialogs =
  | { kind: "edit"; n: NoticeView }
  | { kind: "approve"; n: NoticeView }
  | { kind: "submit"; n: NoticeView }
  | { kind: "notRequired"; n: NoticeView }
  | { kind: "clock"; n: NoticeView }
  | { kind: "extend"; n: NoticeView }
  | { kind: "openCertIn" }
  | { kind: "openDpdp" };

function FormRow({ label, id, children }: { label: string; id: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id} className="text-xs">{label}</Label>
      {children}
    </div>
  );
}

function ActionDialog({ d, props, onClose }: { d: Dialogs; props: CaseNoticesProps; onClose: () => void }) {
  const router = useRouter();
  const [a, setA] = React.useState("");
  const [b, setB] = React.useState("");
  const [c, setC] = React.useState("");
  const [via, setVia] = React.useState(d.kind === "submit" && d.n.kind === "CERT_IN" && props.mail.configured && !props.perms.isClient ? "email" : d.kind === "submit" && d.n.kind === "DPDP_PRINCIPALS" ? "client" : "portal");
  const [cats, setCats] = React.useState<string[]>(props.matches.map((m) => m.code));
  const finish = (msg: string) => () => {
    toast.success(msg);
    onClose();
    router.refresh();
  };
  const run = useMutation({
    mutationFn: async () => {
      switch (d.kind) {
        case "approve":
          return approveNoticeAction(d.n.id, props.perms.isClient ? undefined : { name: a, via: b });
        case "submit":
          return submitNoticeAction(d.n.id, { via, reference: a || undefined, recipientsCount: b ? Number(b) : null, note: c || undefined });
        case "notRequired":
          return notRequiredAction(d.n.id, a);
        case "clock":
          return setClockStartAction(d.n.id, fromLocal(a), b);
        case "extend":
          return extendDeadlineAction(d.n.id, fromLocal(a), b);
        case "openCertIn":
          return openCertInAction(props.caseId, { categories: cats, clockStartAt: a ? fromLocal(a) : null, reason: b || undefined });
        case "openDpdp":
          return openDpdpAction(props.caseId, { awareAt: fromLocal(a || localInput(new Date().toISOString())), principalsAffected: b === "" ? null : Number(b), dataCategories: c.split(",").map((x) => x.trim()).filter(Boolean) });
      }
    },
    onSuccess: finish(
      d.kind === "approve" ? "Approved; it can be filed now"
        : d.kind === "submit" ? (via === "email" ? "Sent to CERT-In" : "Filing recorded")
          : d.kind === "notRequired" ? "Marked not required"
            : d.kind === "openCertIn" ? "CERT-In report opened; the clock is running"
              : d.kind === "openDpdp" ? "DPDP notices opened"
                : "Saved",
    ),
    onError,
  });

  if (d.kind === "edit") return null;
  const title = {
    approve: props.perms.isClient ? "Approve this notice" : "Record the client's approval",
    submit: `File: ${"n" in d ? d.n.label : ""}`,
    notRequired: "Not required",
    clock: "When the clock started",
    extend: "The Board allowed more time",
    openCertIn: "Start a CERT-In report",
    openDpdp: "Record a personal data breach",
  }[d.kind];
  const description = {
    approve: props.perms.isClient ? "It's your organisation's report: check it, then approve it so it can be filed." : "Record who at the client approved it and how. Their name goes on the filing and into the audit trail.",
    submit: "n" in d && d.n.kind === "CERT_IN" ? "Email it to CERT-In from HELIOS with the report attached (the client's point of contact is copied), or record that it was filed another way." : "File it on the Board's platform (or send it to the people affected), then record it here.",
    notRequired: "Say why this notice doesn't need to go out. It stays on the case and can be reopened.",
    clock: "CERT-In's 6 hours run from when the incident was noticed, which may be before this case was opened. The deadline moves with it.",
    extend: "Record the new deadline and the Board's permission.",
    openCertIn: "The 6 hours run from when the incident was noticed: by default, when this case was opened.",
    openDpdp: "The Board and each person affected are to be told without delay, and the Board gets a detailed report within 72 hours of becoming aware.",
  }[d.kind];

  return (
    <div className="flex flex-col gap-3">
      <DialogHeader>
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription>{description}</DialogDescription>
      </DialogHeader>
      {d.kind === "approve" && !props.perms.isClient && (
        <>
          <FormRow label="Approved by (name at the client)" id="ap-name"><Input id="ap-name" className="h-8" value={a} onChange={(e) => setA(e.target.value)} /></FormRow>
          <FormRow label="How (phone, email, meeting…)" id="ap-via"><Input id="ap-via" className="h-8" value={b} onChange={(e) => setB(e.target.value)} /></FormRow>
        </>
      )}
      {d.kind === "submit" && (
        <>
          <FormRow label="How it's filed" id="sub-via">
            <NativeSelect id="sub-via" className="h-8" value={via} onChange={(e) => setVia(e.target.value)}>
              {Object.entries(SUBMIT_CHANNELS)
                .filter(([k]) => k !== "email" || (d.n.kind === "CERT_IN" && !props.perms.isClient))
                .map(([k, v]) => <option key={k} value={k} disabled={k === "email" && !props.mail.configured}>{v}{k === "email" && !props.mail.configured ? " (mail not set up)" : ""}</option>)}
            </NativeSelect>
          </FormRow>
          {via === "email" && <p className="text-xs text-muted-foreground">To incident@cert-in.org.in, with the PDF attached.</p>}
          {!props.mail.configured && d.n.kind === "CERT_IN" && <p className="text-xs text-muted-foreground">{props.mail.reason}</p>}
          {via !== "email" && <FormRow label="Acknowledgement or reference number" id="sub-ref"><Input id="sub-ref" className="h-8" value={a} onChange={(e) => setA(e.target.value)} /></FormRow>}
          {d.n.kind === "DPDP_PRINCIPALS" && <FormRow label="How many people were told" id="sub-count"><Input id="sub-count" type="number" min={1} className="h-8" value={b} onChange={(e) => setB(e.target.value)} /></FormRow>}
          <FormRow label="Note (optional)" id="sub-note"><Input id="sub-note" className="h-8" value={c} onChange={(e) => setC(e.target.value)} /></FormRow>
        </>
      )}
      {d.kind === "notRequired" && <FormRow label="Why" id="nr-why"><Textarea id="nr-why" rows={3} value={a} onChange={(e) => setA(e.target.value)} /></FormRow>}
      {(d.kind === "clock" || d.kind === "extend") && (
        <>
          <FormRow label={d.kind === "clock" ? "Noticed at" : "New deadline"} id="dt"><Input id="dt" type="datetime-local" className="h-8" value={a} onChange={(e) => setA(e.target.value)} /></FormRow>
          <FormRow label={d.kind === "clock" ? "Why this time" : "The Board's permission (reference or message)"} id="dt-why"><Input id="dt-why" className="h-8" value={b} onChange={(e) => setB(e.target.value)} /></FormRow>
        </>
      )}
      {d.kind === "openCertIn" && (
        <>
          <fieldset className="grid max-h-56 gap-1 overflow-y-auto">
            <legend className="text-xs font-medium">Incident type (Annexure I)</legend>
            {props.categories.map((x) => (
              <label key={x.code} className="flex items-start gap-2 text-xs">
                <input type="checkbox" className="mt-0.5" checked={cats.includes(x.code)} onChange={(e) => setCats(e.target.checked ? [...cats, x.code] : cats.filter((y) => y !== x.code))} />
                <span><span className="font-mono">({x.code})</span> {x.label}</span>
              </label>
            ))}
          </fieldset>
          <FormRow label={`Noticed at (blank: when the case was opened, ${formatDateTime(props.createdAt)})`} id="oc-at"><Input id="oc-at" type="datetime-local" className="h-8" value={a} onChange={(e) => setA(e.target.value)} /></FormRow>
          {a && <FormRow label="Why this time" id="oc-why"><Input id="oc-why" className="h-8" value={b} onChange={(e) => setB(e.target.value)} /></FormRow>}
        </>
      )}
      {d.kind === "openDpdp" && (
        <>
          <FormRow label="The client became aware at (blank: now)" id="dp-at"><Input id="dp-at" type="datetime-local" className="h-8" value={a} onChange={(e) => setA(e.target.value)} /></FormRow>
          <FormRow label="People affected (estimate, if known)" id="dp-n"><Input id="dp-n" type="number" min={0} className="h-8" value={b} onChange={(e) => setB(e.target.value)} /></FormRow>
          <FormRow label="Personal data involved (comma-separated: names, phone numbers, Aadhaar, health records…)" id="dp-cat"><Input id="dp-cat" className="h-8" value={c} onChange={(e) => setC(e.target.value)} /></FormRow>
          {!props.dpdpInForce && <p className="text-xs text-muted-foreground">Rule 7 of the DPDP Rules applies from 13 May 2027; until then this runs as a rehearsal of the same steps.</p>}
        </>
      )}
      <DialogFooter>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button onClick={() => run.mutate()} disabled={run.isPending}>{run.isPending && <Loader2 className="animate-spin" />} {d.kind === "submit" && via === "email" ? "Send to CERT-In" : "Confirm"}</Button>
      </DialogFooter>
    </div>
  );
}

// ---------------------------------------------------------------- the card

export function CaseNotices(props: CaseNoticesProps) {
  const router = useRouter();
  const now = useTicking(props.now);
  const [dialog, setDialog] = React.useState<Dialogs | null>(null);
  const simple = useMutation({
    mutationFn: async (x: { op: "request" | "reopen" | "update"; id: string }) => (x.op === "request" ? requestApprovalAction(x.id) : x.op === "reopen" ? reopenNoticeAction(x.id) : addUpdateAction(props.caseId)),
    onSuccess: (_r, x) => {
      toast.success(x.op === "request" ? "Sent to the client for approval" : x.op === "reopen" ? "Reopened" : "Update drafted");
      router.refresh();
    },
    onError,
  });
  const { notices, perms, obligations } = props;
  const hasCertIn = notices.some((n) => n.kind === "CERT_IN");
  const hasDpdp = notices.some((n) => n.kind !== "CERT_IN");

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        {obligations ? (
          <>
            <Badge variant={obligations.certIn ? "soft" : "outline"}>{obligations.certIn ? `CERT-In applies · from ${obligations.minSeverity.toLowerCase()}` : "CERT-In not set for this client"}</Badge>
            <Badge variant={obligations.dpdp ? "soft" : "outline"}>{obligations.dpdp ? "DPDP Data Fiduciary" : "Not a DPDP Data Fiduciary"}</Badge>
          </>
        ) : (
          <span className="text-muted-foreground">An internal case: nothing to report.</span>
        )}
      </div>

      {!hasCertIn && obligations && !perms.isClient && (
        <div className="rounded-md border border-dashed p-3 text-xs">
          {props.matches.length ? (
            <>
              <p className="font-medium">This looks like an incident CERT-In lists:</p>
              <ul className="mt-1 flex flex-col gap-1">
                {props.matches.map((m) => (
                  <li key={m.code}><span className="font-mono">({m.code})</span> {m.label} <span className="text-muted-foreground">— {m.reasons.slice(0, 3).join("; ")}</span></li>
                ))}
              </ul>
              {obligations.certIn && <p className="mt-1 text-muted-foreground">At {obligations.minSeverity.toLowerCase()} severity or above, the report opens on its own and the 6-hour clock starts from when the case was opened.</p>}
            </>
          ) : (
            <p className="text-muted-foreground">Nothing on this case maps to CERT-In&apos;s list of reportable incidents so far.</p>
          )}
          {perms.prepare && (
            <Button size="sm" variant="outline" className="mt-2" onClick={() => setDialog({ kind: "openCertIn" })}><FilePlus2 /> Start a CERT-In report</Button>
          )}
        </div>
      )}

      {notices.map((n) => {
        const open = n.status !== "SUBMITTED" && n.status !== "NOT_REQUIRED";
        const canApprove = perms.isClient ? perms.approve && n.status === "AWAITING_APPROVAL" : perms.prepare && (n.status === "AWAITING_APPROVAL" || n.status === "DRAFT");
        return (
          <div key={n.id} className="flex flex-col gap-2 rounded-md border p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium">{n.label}{n.sequence > 1 ? ` · update ${n.sequence - 1}` : ""}</span>
              <Badge variant={STATUS_VARIANT[n.status]}>{STATUS_LABEL[n.status]}</Badge>
              <ClockChip n={n} now={now} />
              <a href={`/cases/${props.caseId}/notices/${n.id}/pdf`} className="ml-auto inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"><Download className="size-3.5" /> PDF</a>
            </div>
            <p className="text-xs text-muted-foreground">
              To {n.recipient}, {n.deadline}
              {n.dueAt && ` · due ${formatDateTime(n.dueAt)}`} · clock from {formatDateTime(n.clockStartAt)}
              {n.proposedBy === "rules" && " · opened by the rules"}
            </p>
            {n.kind === "CERT_IN" && n.categories.length > 0 && (
              <p className="text-xs">{n.categories.map((c) => `(${c}) ${props.categories.find((x) => x.code === c)?.label ?? c}`).join(" · ")}</p>
            )}
            {open && n.missing.length > 0 && <p className="text-xs text-warning-ink">Still needed: {n.missing.join(", ")}</p>}
            {n.approvedByName && <p className="text-xs"><ShieldCheck className="mr-1 inline size-3.5 text-success-ink" />Approved by {n.approvedByName}{n.approvedVia && n.approvedVia !== "app" ? ` (${n.approvedVia})` : ""}{n.approvedAt ? `, ${formatDateTime(n.approvedAt)}` : ""}</p>}
            {n.submittedAt && <p className="text-xs">Filed {formatDateTime(n.submittedAt)} · {SUBMIT_CHANNELS[n.submittedVia as keyof typeof SUBMIT_CHANNELS] ?? n.submittedVia}{n.reference ? ` · reference ${n.reference}` : ""}{n.recipientsCount ? ` · ${n.recipientsCount.toLocaleString()} people told` : ""}</p>}
            {n.notRequiredReason && <p className="text-xs text-muted-foreground">Not required: {n.notRequiredReason}</p>}
            <div className="flex flex-wrap gap-1.5">
              {open && perms.prepare && <Button size="sm" variant="outline" onClick={() => setDialog({ kind: "edit", n })}><Pencil /> Edit</Button>}
              {n.status === "DRAFT" && perms.prepare && <Button size="sm" variant="outline" disabled={simple.isPending || n.missing.length > 0} onClick={() => simple.mutate({ op: "request", id: n.id })}><Send /> Send for approval</Button>}
              {canApprove && <Button size="sm" disabled={n.missing.length > 0} onClick={() => setDialog({ kind: "approve", n })}><Check /> {perms.isClient ? "Approve" : "Record client approval"}</Button>}
              {n.status === "APPROVED" && (perms.prepare || perms.approve) && <Button size="sm" onClick={() => setDialog({ kind: "submit", n })}><Send /> File</Button>}
              {open && perms.prepare && <Button size="sm" variant="ghost" onClick={() => setDialog({ kind: "clock", n })}><Clock /> Clock start</Button>}
              {open && perms.prepare && n.kind === "DPDP_REPORT" && <Button size="sm" variant="ghost" onClick={() => setDialog({ kind: "extend", n })}>Extension</Button>}
              {open && perms.prepare && <Button size="sm" variant="ghost" onClick={() => setDialog({ kind: "notRequired", n })}><X /> Not required</Button>}
              {n.status === "NOT_REQUIRED" && perms.prepare && <Button size="sm" variant="ghost" disabled={simple.isPending} onClick={() => simple.mutate({ op: "reopen", id: n.id })}><RotateCcw /> Reopen</Button>}
              {n.kind === "CERT_IN" && n.status === "SUBMITTED" && n.latest && perms.prepare && <Button size="sm" variant="outline" disabled={simple.isPending} onClick={() => simple.mutate({ op: "update", id: n.id })}><FilePlus2 /> Send an update</Button>}
            </div>
          </div>
        );
      })}

      {!hasDpdp && obligations && perms.prepare && (
        <Button size="sm" variant="outline" className="w-fit" onClick={() => setDialog({ kind: "openDpdp" })}><FilePlus2 /> Personal data was breached</Button>
      )}

      <Dialog open={!!dialog} onOpenChange={(o) => !o && setDialog(null)}>
        <DialogContent className={dialog?.kind === "edit" ? "sm:max-w-3xl" : undefined}>
          {dialog?.kind === "edit" ? (
            <>
              <DialogHeader>
                <DialogTitle>{dialog.n.label}</DialogTitle>
                <DialogDescription>Drafted from the case. Edit anything; once it&apos;s been approved, a change sends it back for approval.</DialogDescription>
              </DialogHeader>
              <NoticeEditor n={dialog.n} categories={props.categories} onClose={() => setDialog(null)} />
            </>
          ) : dialog ? (
            <ActionDialog key={dialog.kind + ("n" in dialog ? dialog.n.id : "")} d={dialog} props={props} onClose={() => setDialog(null)} />
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
