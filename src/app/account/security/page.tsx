import Link from "next/link";
import { redirect } from "next/navigation";
import { ArrowLeft, ShieldCheck } from "lucide-react";

import { db } from "@/lib/db";
import { currentUser } from "@/lib/session";
import { getSetting } from "@/lib/settings";
import { isClientRole } from "@/lib/rbac";
import { SSO } from "@/lib/sso";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { MfaSetup } from "@/components/account/mfa-setup";

// Outside the app shell on purpose: an account that must set up two-step
// sign-in lands here and can't reach anything else until it has.
export default async function SecurityPage() {
  const user = await currentUser();
  if (!user) redirect("/login");
  const [me, policy] = await Promise.all([
    db.user.findUniqueOrThrow({ where: { id: user.id }, select: { email: true, mfaEnabledAt: true, mfaRecoveryHashes: true, lastLoginAt: true } }),
    getSetting("security.mfa"),
  ]);
  const required = policy === "everyone" || (policy === "staff" && !isClientRole(user.role));
  return (
    <div className="flex min-h-screen items-start justify-center bg-muted/30 px-4 py-10">
      <div className="flex w-full max-w-lg flex-col gap-4">
        {!user.mfaPending && (
          <Link href="/" className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="size-4" /> Back to HELIOS
          </Link>
        )}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg"><ShieldCheck className="size-5" /> Sign-in security</CardTitle>
            <CardDescription>
              {me.email}
              {user.mfaPending ? " · Your organization requires two-step sign-in. Set it up to continue." : ""}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <MfaSetup enabled={!!me.mfaEnabledAt} enabledAt={me.mfaEnabledAt?.toISOString() ?? null} recoveryLeft={me.mfaRecoveryHashes.length} required={required} ssoName={SSO && !user.isClient ? SSO.name : null} />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
