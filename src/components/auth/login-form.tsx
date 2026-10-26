"use client";

import * as React from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { signIn } from "next-auth/react";
import { KeyRound, ShieldHalf, Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

// What the server's sign-in codes (lib/auth.ts) and SSO refusals mean.
const MESSAGES: Record<string, string> = {
  mfa_invalid: "That code doesn't match. Use the current code from your app, or a recovery code.",
  sso_required: "Staff sign in with single sign-on.",
  sso_unknown: "There's no active HELIOS staff account for that address. Ask an administrator to invite you.",
  sso_unverified: "Your identity provider didn't confirm that email address.",
};

export function LoginForm({ sso }: { sso: { name: string } | null }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get("callbackUrl") ?? "/";

  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [code, setCode] = React.useState("");
  const [step, setStep] = React.useState<"password" | "code">("password");
  const [error, setError] = React.useState<string | null>(MESSAGES[searchParams.get("error") ?? ""] ?? null);
  const [loading, setLoading] = React.useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const result = await signIn("credentials", {
      email,
      password,
      ...(step === "code" ? { code } : {}),
      redirect: false,
    });

    setLoading(false);

    if (result?.error) {
      if (result.code === "mfa_required") {
        setStep("code");
        return;
      }
      setError(MESSAGES[result.code ?? ""] ?? "Invalid email or password.");
      if (result.code === "mfa_invalid") setCode("");
      return;
    }

    router.push(callbackUrl);
    router.refresh();
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-muted/30 px-4">
      <Card className="w-full max-w-sm">
        <CardHeader className="items-center text-center">
          <div className="mb-2 flex size-10 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <ShieldHalf className="size-5" />
          </div>
          <CardTitle className="text-xl">Sign in to HELIOS</CardTitle>
          <CardDescription>
            {step === "code" ? "Enter the 6-digit code from your authenticator app" : "Unified security operations platform"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSubmit} className="flex flex-col gap-4">
            {step === "password" ? (
              <>
                <div className="flex flex-col gap-2">
                  <Label htmlFor="email">Email</Label>
                  <Input id="email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
                </div>
                <div className="flex flex-col gap-2">
                  <Label htmlFor="password">Password</Label>
                  <Input id="password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
                </div>
              </>
            ) : (
              <div className="flex flex-col gap-2">
                <Label htmlFor="code">Code</Label>
                <Input id="code" inputMode="numeric" autoComplete="one-time-code" autoFocus required value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" />
                <p className="text-xs text-muted-foreground">Lost your phone? Enter one of your recovery codes instead.</p>
              </div>
            )}
            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}
            <Button type="submit" disabled={loading} className="mt-2">
              {loading && <Loader2 className="animate-spin" />}
              {step === "code" ? "Verify" : "Sign in"}
            </Button>
            {step === "code" && (
              <Button type="button" variant="ghost" size="sm" onClick={() => { setStep("password"); setCode(""); setError(null); }}>
                Use a different account
              </Button>
            )}
          </form>
          {sso && step === "password" && (
            <div className="mt-4 flex flex-col gap-2 border-t pt-4">
              <Button type="button" variant="outline" onClick={() => signIn("sso", { callbackUrl })}>
                <KeyRound /> Sign in with {sso.name}
              </Button>
              <p className="text-center text-[11px] text-muted-foreground">For HELIOS staff</p>
            </div>
          )}
        </CardContent>
      </Card>
      <Link href="/home" className="mt-4 text-xs text-muted-foreground hover:text-foreground hover:underline">
        ← Back to the website
      </Link>
    </div>
  );
}
