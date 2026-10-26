"use server";

import QRCode from "qrcode";
import { z } from "zod";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { requireUserForMfaSetup } from "@/lib/session";
import { seal, unseal } from "@/lib/secrets";
import { consumeRecoveryCode, newRecoveryCodes, newSecret, otpauthUri, verifyTotp } from "@/lib/mfa";
import { getSetting } from "@/lib/settings";
import { isClientRole } from "@/lib/rbac";

// Setting up and managing two-step sign-in for the signed-in account. The
// secret is stored sealed from the first step but only switched on once a
// code from the app proves it was scanned.

const code = z.string().trim().min(6).max(20);

async function required(role: string) {
  const policy = await getSetting("security.mfa");
  return policy === "everyone" || (policy === "staff" && !isClientRole(role as never));
}

export async function startMfaSetupAction() {
  const user = await requireUserForMfaSetup();
  const me = await db.user.findUniqueOrThrow({ where: { id: user.id }, select: { email: true, mfaEnabledAt: true } });
  if (me.mfaEnabledAt) throw new Error("Two-step sign-in is already on");
  const secret = newSecret();
  await db.user.update({ where: { id: user.id }, data: { mfaSecretCipher: seal(secret), mfaLastStep: null } });
  const company = (await getSetting("company.profile")).name || "HELIOS";
  const uri = otpauthUri(secret, me.email, company.replace(/:/g, ""));
  return { secret, uri, qr: await QRCode.toDataURL(uri, { margin: 1, width: 220 }) };
}

export async function confirmMfaAction(input: string) {
  const user = await requireUserForMfaSetup();
  const me = await db.user.findUniqueOrThrow({ where: { id: user.id }, select: { mfaSecretCipher: true, mfaEnabledAt: true } });
  if (!me.mfaSecretCipher || me.mfaEnabledAt) throw new Error("Start the setup again");
  const step = verifyTotp(unseal(me.mfaSecretCipher), code.parse(input));
  if (step === null) throw new Error("That code doesn't match: check the app's clock and try the next code");
  const { codes, hashes } = newRecoveryCodes();
  await db.user.update({ where: { id: user.id }, data: { mfaEnabledAt: new Date(), mfaLastStep: step, mfaRecoveryHashes: hashes } });
  await logAction({ actorId: user.id, action: "auth.mfa_enabled" });
  return { recoveryCodes: codes };
}

async function proveSecondStep(userId: string, input: string) {
  const me = await db.user.findUniqueOrThrow({ where: { id: userId }, select: { mfaSecretCipher: true, mfaEnabledAt: true, mfaLastStep: true, mfaRecoveryHashes: true, role: true } });
  if (!me.mfaEnabledAt || !me.mfaSecretCipher) throw new Error("Two-step sign-in isn't on");
  const value = code.parse(input);
  const step = verifyTotp(unseal(me.mfaSecretCipher), value, { lastStep: me.mfaLastStep });
  if (step !== null) {
    await db.user.update({ where: { id: userId }, data: { mfaLastStep: step } });
    return me;
  }
  const left = consumeRecoveryCode(me.mfaRecoveryHashes, value);
  if (!left) throw new Error("That code doesn't match");
  await db.user.update({ where: { id: userId }, data: { mfaRecoveryHashes: left } });
  return me;
}

export async function newRecoveryCodesAction(input: string) {
  const user = await requireUserForMfaSetup();
  await proveSecondStep(user.id, input);
  const { codes, hashes } = newRecoveryCodes();
  await db.user.update({ where: { id: user.id }, data: { mfaRecoveryHashes: hashes } });
  await logAction({ actorId: user.id, action: "auth.recovery_codes_renewed" });
  return { recoveryCodes: codes };
}

export async function disableMfaAction(input: string) {
  const user = await requireUserForMfaSetup();
  const me = await proveSecondStep(user.id, input);
  if (await required(me.role)) throw new Error("Your organization requires two-step sign-in for this account");
  await db.user.update({ where: { id: user.id }, data: { mfaEnabledAt: null, mfaSecretCipher: null, mfaRecoveryHashes: [], mfaLastStep: null } });
  await logAction({ actorId: user.id, action: "auth.mfa_disabled" });
}
