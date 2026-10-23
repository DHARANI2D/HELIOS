import { auth } from "@/lib/auth";

// Server Actions are public POST endpoints — the proxy redirect and
// render-time gating are not a security boundary (see the Next.js Server
// Actions guide), so every mutating action calls one of these first.

export interface SessionUser {
  id: string;
  role: string;
  name?: string | null;
  email?: string | null;
}

export async function requireUser(): Promise<SessionUser> {
  const session = await auth();
  if (!session?.user?.id) throw new Error("Unauthorized");
  return {
    id: session.user.id,
    role: session.user.role ?? "ANALYST",
    name: session.user.name,
    email: session.user.email,
  };
}

// Destructive or org-wide operations (global purge, playbook authoring,
// approving containment) are admin-only.
export async function requireAdmin(): Promise<SessionUser> {
  const user = await requireUser();
  if (user.role !== "ADMIN") throw new Error("Forbidden: admin role required");
  return user;
}
