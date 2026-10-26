import NextAuth, { CredentialsSignin } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { PrismaAdapter } from "@auth/prisma-adapter";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { isClientRole } from "@/lib/rbac";
import { SSO } from "@/lib/sso";
import { SignInStep, verifyCredentials } from "@/lib/credentials";

// The sign-in form reads these codes to ask for the next step (lib/credentials).
class StepRequired extends CredentialsSignin {
  constructor(code: string) {
    super();
    this.code = code;
  }
}

export const { handlers, auth, signIn, signOut } = NextAuth({
  adapter: PrismaAdapter(db),
  session: { strategy: "jwt" },
  pages: {
    signIn: "/login",
  },
  providers: [
    Credentials({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
        code: { label: "Code", type: "text" },
      },
      authorize: async (credentials) => {
        try {
          return await verifyCredentials(credentials?.email as string | undefined, credentials?.password as string | undefined, (credentials?.code as string | undefined)?.trim());
        } catch (err) {
          if (err instanceof SignInStep) throw new StepRequired(err.code);
          throw err;
        }
      },
    }),
    ...(SSO
      ? [
          {
            id: SSO.id,
            name: SSO.name,
            type: "oidc" as const,
            issuer: SSO.issuer,
            clientId: process.env.HELIOS_SSO_CLIENT_ID,
            clientSecret: process.env.HELIOS_SSO_CLIENT_SECRET,
            // The company's own identity provider vouches for the address.
            allowDangerousEmailAccountLinking: true,
            checks: ["pkce" as const, "state" as const],
          },
        ]
      : []),
  ],
  callbacks: {
    signIn: async ({ account, profile, user }) => {
      if (account?.provider !== "sso") return true;
      const email = String(profile?.email ?? user.email ?? "").toLowerCase();
      if (!email || profile?.email_verified === false) return "/login?error=sso_unverified";
      const staff = await db.user.findUnique({ where: { email } });
      // No new accounts from SSO, and no client accounts: invite people first.
      if (!staff || !staff.active || staff.tenantId || isClientRole(staff.role)) {
        await logAction({ action: "auth.sso_refused", detail: { email, reason: !staff ? "no account" : !staff.active ? "inactive" : "client account" } });
        return "/login?error=sso_unknown";
      }
      await db.user.update({ where: { id: staff.id }, data: { lastLoginAt: new Date(), failedLogins: 0, lockedUntil: null } });
      await logAction({ actorId: staff.id, action: "auth.signed_in", detail: { method: "sso", issuer: SSO?.issuer } });
      return true;
    },
    jwt: async ({ token, user, account }) => {
      if (user) {
        token.id = user.id;
        token.role = (user as { role?: string }).role;
        token.via = account?.provider === "sso" ? "sso" : "password";
      }
      return token;
    },
    session: async ({ session, token }) => {
      if (session.user) {
        session.user.id = token.id as string;
        session.user.role = token.role as string;
        session.user.via = token.via;
      }
      return session;
    },
  },
});
