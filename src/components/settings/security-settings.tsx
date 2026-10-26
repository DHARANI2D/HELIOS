"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { KeySquare, Loader2, Save } from "lucide-react";
import { toast } from "sonner";

import { adoptClientKeysAction, saveSecuritySettingsAction } from "@/app/(app)/settings/actions";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";

interface Props {
  mfa: "optional" | "staff" | "everyone";
  ssoOnlyForStaff: boolean;
  sso: string | null;
  staffWithoutMfa: number;
  keys: { master: string; clientsWithKeys: number; onClientKeys: number; onMasterKey: number };
  canEdit: boolean;
  isAdmin: boolean;
}

const MASTER: Record<string, string> = {
  "aws-kms": "AWS KMS (decrypted at startup)",
  environment: "HELIOS_ENCRYPTION_KEY",
  "derived-from-auth-secret": "derived from AUTH_SECRET: set HELIOS_ENCRYPTION_KEY or use KMS in production",
};

export function SecuritySettings(props: Props) {
  const router = useRouter();
  const [mfa, setMfa] = React.useState(props.mfa);
  const [ssoOnly, setSsoOnly] = React.useState(props.ssoOnlyForStaff);
  const onError = (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed");
  const save = useMutation({ mutationFn: () => saveSecuritySettingsAction({ mfa, ssoOnlyForStaff: ssoOnly }), onSuccess: () => { toast.success("Sign-in rules saved"); router.refresh(); }, onError });
  const adopt = useMutation({ mutationFn: () => adoptClientKeysAction(), onSuccess: (r) => { toast.success(`${r.moved} client credential${r.moved === 1 ? "" : "s"} moved onto their client's own key`); router.refresh(); }, onError });

  return (
    <div className="grid gap-5">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="grid gap-1.5">
          <Label htmlFor="sec-mfa">Two-step sign-in required for</Label>
          <NativeSelect id="sec-mfa" value={mfa} onChange={(e) => setMfa(e.target.value as Props["mfa"])} disabled={!props.canEdit}>
            <option value="optional">Nobody (each person may turn it on)</option>
            <option value="staff">All SOC staff</option>
            <option value="everyone">Everyone, client users too</option>
          </NativeSelect>
          <p className="text-[11px] text-muted-foreground">
            Accounts it applies to set it up at their next sign-in and can&apos;t use HELIOS until they have.
            {props.staffWithoutMfa ? ` ${props.staffWithoutMfa} active staff account${props.staffWithoutMfa === 1 ? " doesn't" : "s don't"} use it yet.` : " Every active staff account uses it."}
          </p>
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="sec-sso">Single sign-on</Label>
          <p className="text-sm">{props.sso ? <Badge variant="success">{props.sso}</Badge> : <Badge variant="outline">not configured</Badge>}</p>
          <div className="flex items-center gap-2">
            <Switch id="sec-sso" checked={ssoOnly} onCheckedChange={setSsoOnly} disabled={!props.canEdit || !props.sso} />
            <span className="text-sm">Staff must use single sign-on</span>
          </div>
          <p className="text-[11px] text-muted-foreground">
            {props.sso ? "Staff then can't sign in with a password; your identity provider enforces MFA." : "Set HELIOS_SSO_ISSUER, HELIOS_SSO_CLIENT_ID and HELIOS_SSO_CLIENT_SECRET (any OpenID Connect provider) to turn it on."}
          </p>
        </div>
      </div>
      {props.canEdit && (
        <Button className="w-fit" onClick={() => save.mutate()} disabled={save.isPending}>{save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save sign-in rules</Button>
      )}

      <div className="grid gap-2 border-t pt-4">
        <p className="text-sm font-medium">Encryption of stored credentials</p>
        <p className="text-xs text-muted-foreground">
          Master key: {MASTER[props.keys.master] ?? props.keys.master}. Each client&apos;s credentials are sealed with that client&apos;s own data key, itself wrapped by the master key:
          {` ${props.keys.clientsWithKeys} client${props.keys.clientsWithKeys === 1 ? "" : "s"} with a key, ${props.keys.onClientKeys} credential${props.keys.onClientKeys === 1 ? "" : "s"} on them`}
          {props.keys.onMasterKey ? `, ${props.keys.onMasterKey} still on the master key.` : "."}
        </p>
        {props.isAdmin && props.keys.onMasterKey > 0 && (
          <Button size="sm" variant="outline" className="w-fit" onClick={() => adopt.mutate()} disabled={adopt.isPending}>
            {adopt.isPending ? <Loader2 className="animate-spin" /> : <KeySquare />} Move them onto their clients&apos; keys
          </Button>
        )}
      </div>
    </div>
  );
}
