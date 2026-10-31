"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { KeyRound, Loader2, Pencil, ShieldOff, UserPlus } from "lucide-react";
import { toast } from "sonner";
import type { SecurityDomain, UserRole } from "@prisma/client";

import { inviteUserAction, resetMfaAction, resetPasswordAction, setUserActiveAction, updateUserAction } from "@/app/(app)/team/actions";
import { DOMAIN_LABEL, ROLES, ROLE_ORDER, SECURITY_DOMAINS } from "@/lib/rbac";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { CopyField } from "@/components/integrations/onboard-wizard";
import { unwrap } from "@/lib/action-result";

export interface UserDraft {
  id?: string;
  name: string;
  email: string;
  role: UserRole;
  tenantId: string | null;
  domains: SecurityDomain[];
  title: string;
}

const EMPTY: UserDraft = { name: "", email: "", role: "TRIAGE_ANALYST", tenantId: null, domains: [], title: "" };

function Credentials({ creds, onClose }: { creds: { email: string; password: string } | null; onClose: () => void }) {
  return (
    <Dialog open={!!creds} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Temporary password</DialogTitle>
          <DialogDescription>Shown once. Send it over a separate channel from the email address; they should change it after first sign-in.</DialogDescription>
        </DialogHeader>
        {creds && (
          <div className="grid gap-3">
            <CopyField label="Email" value={creds.email} />
            <CopyField label="Password" value={creds.password} />
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

export function UserDialogButton({ initial, tenants }: { initial?: UserDraft; tenants: Array<{ id: string; name: string }> }) {
  const router = useRouter();
  const [open, setOpen] = React.useState(false);
  const [d, setD] = React.useState<UserDraft>(initial ?? EMPTY);
  const [creds, setCreds] = React.useState<{ email: string; password: string } | null>(null);
  const client = !!ROLES[d.role].client;

  const save = useMutation({
    mutationFn: async () => {
      const payload = { name: d.name, role: d.role, tenantId: client ? d.tenantId : null, domains: client ? [] : d.domains, title: d.title };
      if (d.id) {
        await unwrap(updateUserAction(d.id, payload));
        return null;
      }
      return unwrap(inviteUserAction({ ...payload, email: d.email }));
    },
    onSuccess: (r) => {
      toast.success(d.id ? "User updated" : "User invited");
      setOpen(false);
      if (r) {
        setCreds(r);
        setD(EMPTY);
      }
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });

  return (
    <>
      <Button size={initial ? "icon" : "sm"} variant={initial ? "ghost" : "default"} className={cn(initial && "size-7")} onClick={() => setOpen(true)} aria-label={initial ? "Edit user" : undefined}>
        {initial ? <Pencil /> : <><UserPlus /> Invite user</>}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{d.id ? "Edit user" : "Invite user"}</DialogTitle>
            <DialogDescription>{ROLES[d.role].description}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label>Name</Label>
              <Input value={d.name} onChange={(e) => setD({ ...d, name: e.target.value })} />
            </div>
            <div className="grid gap-1.5">
              <Label>Email</Label>
              <Input type="email" value={d.email} onChange={(e) => setD({ ...d, email: e.target.value })} disabled={!!d.id} />
            </div>
            <div className="grid gap-1.5">
              <Label>Role</Label>
              <NativeSelect value={d.role} onChange={(e) => setD({ ...d, role: e.target.value as UserRole })}>
                {ROLE_ORDER.map((r) => (
                  <option key={r} value={r}>{ROLES[r].label} ({ROLES[r].group})</option>
                ))}
              </NativeSelect>
            </div>
            {client ? (
              <div className="grid gap-1.5">
                <Label>Client</Label>
                <NativeSelect value={d.tenantId ?? ""} onChange={(e) => setD({ ...d, tenantId: e.target.value || null })}>
                  <option value="">Choose a client…</option>
                  {tenants.map((t) => (
                    <option key={t.id} value={t.id}>{t.name}</option>
                  ))}
                </NativeSelect>
              </div>
            ) : (
              <div className="grid gap-1.5">
                <Label>Title</Label>
                <Input value={d.title} onChange={(e) => setD({ ...d, title: e.target.value })} />
              </div>
            )}
          </div>
          {!client && (
            <div className="grid gap-1.5">
              <Label>Queues (security domains)</Label>
              <div className="flex flex-wrap gap-1.5">
                {SECURITY_DOMAINS.map((dom) => {
                  const on = d.domains.includes(dom);
                  return (
                    <button
                      key={dom}
                      type="button"
                      onClick={() => setD({ ...d, domains: on ? d.domains.filter((x) => x !== dom) : [...d.domains, dom] })}
                      className={cn("rounded-full border px-2.5 py-0.5 text-xs hover:bg-accent", on && "border-primary bg-primary/15 text-primary")}
                    >
                      {DOMAIN_LABEL[dom]}
                    </button>
                  );
                })}
              </div>
              <p className="text-[11px] text-muted-foreground">No queues = sees every domain. Roles with &quot;see every queue&quot; ignore this.</p>
            </div>
          )}
          <DialogFooter>
            <Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={() => save.mutate()} disabled={save.isPending || d.name.trim().length < 2 || (!d.id && !d.email) || (client && !d.tenantId)}>
              {save.isPending && <Loader2 className="animate-spin" />}
              {d.id ? "Save" : "Invite"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Credentials creds={creds} onClose={() => setCreds(null)} />
    </>
  );
}

export function UserRowControls({ userId, active, self, mfa }: { userId: string; active: boolean; self: boolean; mfa: boolean }) {
  const router = useRouter();
  const [creds, setCreds] = React.useState<{ email: string; password: string } | null>(null);
  const toggle = useMutation({
    mutationFn: (on: boolean) => unwrap(setUserActiveAction(userId, on)),
    onSuccess: () => router.refresh(),
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  const reset = useMutation({
    mutationFn: () => unwrap(resetPasswordAction(userId)),
    onSuccess: (r) => setCreds(r),
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  const resetMfa = useMutation({
    mutationFn: () => unwrap(resetMfaAction(userId)),
    onSuccess: () => {
      toast.success("Two-step sign-in reset: they set it up again at their next sign-in");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed"),
  });
  return (
    <div className="flex items-center justify-end gap-1">
      {mfa && !self && (
        <Button size="icon" variant="ghost" className="size-7" aria-label="Reset two-step sign-in" title="Reset two-step sign-in (lost phone)" onClick={() => resetMfa.mutate()} disabled={resetMfa.isPending}>
          {resetMfa.isPending ? <Loader2 className="animate-spin" /> : <ShieldOff />}
        </Button>
      )}
      <Button size="icon" variant="ghost" className="size-7" aria-label="Reset password" onClick={() => reset.mutate()} disabled={reset.isPending}>
        {reset.isPending ? <Loader2 className="animate-spin" /> : <KeyRound />}
      </Button>
      <Switch checked={active} onCheckedChange={(on) => toggle.mutate(on)} disabled={self} aria-label="Active" />
      <Credentials creds={creds} onClose={() => setCreds(null)} />
    </div>
  );
}
