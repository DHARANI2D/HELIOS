import { unstable_rethrow } from "next/navigation";
import { Prisma } from "@prisma/client";
import { ZodError } from "zod";

import type { ActionResult } from "@/lib/action-result";

// Wraps a server action so a refusal comes back as a value. In a production
// build Next replaces a thrown error's message with a generic one, so the
// person would never see why ("keep logs for at least 180 days"). Messages
// HELIOS writes for people pass through; database, system and programming
// errors are logged and reported generically, so they don't leak internals.
// Next's own control flow (redirect, notFound) is rethrown.

const GENERIC = "Something went wrong. The details are in the server log.";

export function publicMessage(e: unknown): string {
  if (e instanceof ZodError) {
    const issue = e.issues[0];
    return issue ? (issue.path.length ? `${issue.path.join(".")}: ${issue.message}` : issue.message) : "That isn't valid";
  }
  if (e instanceof Prisma.PrismaClientKnownRequestError) {
    if (e.code === "P2025") return "Not found";
    if (e.code === "P2002") return "That already exists";
    if (e.code === "P2003") return "It's still in use elsewhere";
  }
  if (!(e instanceof Error) || e.name.startsWith("PrismaClient") || e instanceof TypeError || e instanceof ReferenceError || e instanceof RangeError) return GENERIC;
  // Node's system errors (ENOENT, ECONNREFUSED...) name paths and hosts.
  const code = (e as { code?: unknown }).code;
  if (typeof code === "string" && /^E[A-Z]+$/.test(code)) return GENERIC;
  return e.message || GENERIC;
}

export function action<A extends unknown[], T>(run: (...args: A) => Promise<T>): (...args: A) => Promise<ActionResult<T>> {
  return async (...args: A) => {
    try {
      return { ok: true, value: await run(...args) };
    } catch (e) {
      unstable_rethrow(e);
      const error = publicMessage(e);
      if (error === GENERIC) console.error("Server action failed", e);
      return { ok: false, error };
    }
  };
}
