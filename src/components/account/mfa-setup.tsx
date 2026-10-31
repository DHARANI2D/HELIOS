"use client";

import * as React from "react";
import Image from "next/image";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Check, Copy, KeyRound, Loader2, ShieldOff } from "lucide-react";
import { toast } from "sonner";

import { confirmMfaAction, disableMfaAction, newRecoveryCodesAction, startMfaSetupAction } from "@/app/account/security/actions";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { unwrap } from "@/lib/action-result";

interface Props {
  enabled: boolean;
  enabledAt: string | null;
  recoveryLeft: number;
  required: boolean;
  ssoName: string | null;
}

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <div className="grid gap-3 rounded-md border border-warning/40 bg-warning/10 p-3">
      <p className="text-sm font-medium">Save these recovery codes now</p>
      <p className="text-xs text-muted-foreground">Each one signs you in once if you lose your phone. They won&apos;t be shown again.</p>
      <ul className="grid grid-cols-2 gap-1 font-mono text-sm">{codes.map((c) => <li key={c}>{c}</li>)}</ul>
      <div className="flex gap-2">
        <Button size="sm" variant="outline" onClick={() => navigator.clipboard.writeText(codes.join("\n")).then(() => setCopied(true))}>{copied ? <Check /> : <Copy />} Copy</Button>
        <Button size="sm" onClick={onDone}>I&apos;ve saved them</Button>
      </div>
    </div>
  );
}

export function MfaSetup({ enabled, enabledAt, recoveryLeft, required, ssoName }: Props) {
  const router = useRouter();
  const [setup, setSetup] = React.useState<{ secret: string; qr: string } | null>(null);
  const [code, setCode] = React.useState("");
  const [codes, setCodes] = React.useState<string[] | null>(null);
  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed");
  const start = useMutation({ mutationFn: () => unwrap(startMfaSetupAction()), onSuccess: (r) => setSetup({ secret: r.secret, qr: r.qr }), onError });
  const confirm = useMutation({
    mutationFn: () => unwrap(confirmMfaAction(code)),
    onSuccess: (r) => {
      setCodes(r.recoveryCodes);
      setSetup(null);
      setCode("");
      toast.success("Two-step sign-in is on");
    },
    onError,
  });
  const renew = useMutation({ mutationFn: () => unwrap(newRecoveryCodesAction(code)), onSuccess: (r) => { setCodes(r.recoveryCodes); setCode(""); }, onError });
  const disable = useMutation({
    mutationFn: () => unwrap(disableMfaAction(code)),
    onSuccess: () => {
      toast.success("Two-step sign-in is off");
      setCode("");
      router.refresh();
    },
    onError,
  });

  if (codes) return <RecoveryCodes codes={codes} onDone={() => { setCodes(null); router.push("/"); router.refresh(); }} />;

  if (enabled) {
    return (
      <div className="grid gap-4">
        <p className="flex items-center gap-2 text-sm">
          <Badge variant="success">On</Badge> since {enabledAt ? new Date(enabledAt).toLocaleDateString() : "—"} · {recoveryLeft} recovery code{recoveryLeft === 1 ? "" : "s"} left
        </p>
        <div className="grid gap-1.5">
          <Label htmlFor="mfa-code">A code from your app (or a recovery code)</Label>
          <Input id="mfa-code" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" />
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={() => renew.mutate()} disabled={!code || renew.isPending}>{renew.isPending ? <Loader2 className="animate-spin" /> : <KeyRound />} New recovery codes</Button>
          {!required && (
            <Button variant="outline" onClick={() => disable.mutate()} disabled={!code || disable.isPending}>{disable.isPending ? <Loader2 className="animate-spin" /> : <ShieldOff />} Turn off</Button>
          )}
        </div>
        {required && <p className="text-xs text-muted-foreground">Your organization requires it, so it can&apos;t be turned off.</p>}
      </div>
    );
  }

  return (
    <div className="grid gap-4">
      <p className="text-sm text-muted-foreground">
        Sign in with your password and a 6-digit code from an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password, Authy…).
        {ssoName ? ` Signing in with ${ssoName} uses your identity provider's own MFA instead.` : ""}
      </p>
      {!setup ? (
        <Button className="w-fit" onClick={() => start.mutate()} disabled={start.isPending}>{start.isPending ? <Loader2 className="animate-spin" /> : <KeyRound />} Set up two-step sign-in</Button>
      ) : (
        <div className="grid gap-3">
          <ol className="list-decimal space-y-1 pl-5 text-sm">
            <li>Scan this code with your authenticator app.</li>
            <li>Enter the 6-digit code it shows.</li>
          </ol>
          {/* A data: URL from the server; nothing loads from elsewhere. */}
          <Image src={setup.qr} alt="QR code for your authenticator app" width={220} height={220} unoptimized className="rounded-md border bg-white p-1" />
          <p className="text-xs text-muted-foreground">Can&apos;t scan? Enter this key: <code className="break-all font-mono">{setup.secret.match(/.{1,4}/g)?.join(" ")}</code></p>
          <div className="grid gap-1.5">
            <Label htmlFor="mfa-confirm">Code from the app</Label>
            <Input id="mfa-confirm" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" />
          </div>
          <Button className="w-fit" onClick={() => confirm.mutate()} disabled={code.length < 6 || confirm.isPending}>{confirm.isPending ? <Loader2 className="animate-spin" /> : <Check />} Turn on</Button>
        </div>
      )}
    </div>
  );
}
