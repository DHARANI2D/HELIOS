import bcrypt from "bcryptjs";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { unseal } from "@/lib/secrets";
import { consumeRecoveryCode, verifyTotp } from "@/lib/mfa";
import { getSetting } from "@/lib/settings";
import { isClientRole } from "@/lib/rbac";
import { SSO } from "@/lib/sso";

// The password and second-step check behind the sign-in form (lib/auth).
// Five wrong passwords or second-step codes lock the account for 15
// minutes. The lockout is per account, so a password-spraying run against
// many accounts still trips it.
const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

// What the form needs to do next: ask for a code, say the code was wrong,
// or send staff to single sign-on.
export class SignInStep extends Error {
  constructor(readonly code: "mfa_required" | "mfa_invalid" | "sso_required") {
    super(code);
  }
}

async function failed(user: { id: string; failedLogins: number }, reason: string) {
  const count = user.failedLogins + 1;
  await db.user.update({ where: { id: user.id }, data: count >= MAX_FAILED_LOGINS ? { failedLogins: 0, lockedUntil: new Date(Date.now() + LOCKOUT_MS) } : { failedLogins: count } });
  await logAction({ actorId: user.id, action: "auth.sign_in_failed", detail: { reason, locked: count >= MAX_FAILED_LOGINS } });
}

// The account, or null for a wrong, unknown or locked one; throws a
// SignInStep when the form has another step to show.
export async function verifyCredentials(email: string | undefined, password: string | undefined, code: string | undefined) {
  if (!email || !password) return null;

  const user = await db.user.findUnique({ where: { email: email.toLowerCase().trim() }, include: { tenant: { select: { status: true } } } });
  if (!user?.passwordHash || !user.active || user.tenant?.status === "SUSPENDED") return null;
  if (user.lockedUntil && user.lockedUntil > new Date()) return null;

  if (!(await bcrypt.compare(password, user.passwordHash))) {
    await failed(user, "password");
    return null;
  }
  // Only after the password is right, so this says nothing about other accounts.
  if (SSO && !isClientRole(user.role) && (await getSetting("security.ssoOnlyForStaff"))) throw new SignInStep("sso_required");

  const data: { failedLogins: number; lockedUntil: null; lastLoginAt: Date; mfaLastStep?: number; mfaRecoveryHashes?: string[] } = { failedLogins: 0, lockedUntil: null, lastLoginAt: new Date() };
  if (user.mfaEnabledAt && user.mfaSecretCipher) {
    if (!code) throw new SignInStep("mfa_required");
    const step = verifyTotp(unseal(user.mfaSecretCipher), code, { lastStep: user.mfaLastStep });
    if (step !== null) data.mfaLastStep = step;
    else {
      const left = consumeRecoveryCode(user.mfaRecoveryHashes, code);
      if (!left) {
        await failed(user, "second_step");
        throw new SignInStep("mfa_invalid");
      }
      data.mfaRecoveryHashes = left;
      await logAction({ actorId: user.id, action: "auth.recovery_code_used", detail: { remaining: left.length } });
    }
  }
  await db.user.update({ where: { id: user.id }, data });
  await logAction({ actorId: user.id, action: "auth.signed_in", detail: { method: user.mfaEnabledAt ? "password+totp" : "password" } });
  return { id: user.id, email: user.email, name: user.name, role: user.role };
}
