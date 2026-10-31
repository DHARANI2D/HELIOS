"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { requirePermission } from "@/lib/session";
import { issueApiToken, revokeApiToken } from "@/lib/api/tokens";
import { action } from "@/lib/action";

const createSchema = z.object({
  name: z.string().trim().min(2).max(80),
  canWrite: z.boolean(),
  expiresInDays: z.union([z.literal(30), z.literal(90), z.literal(365), z.null()]),
});

// Returns the token string — the only time it exists outside a hash.
export const createApiTokenAction = action(async function createApiTokenAction(input: z.input<typeof createSchema>) {
  const user = await requirePermission("api.tokens");
  const { token } = await issueApiToken(user, createSchema.parse(input));
  revalidatePath("/api-tokens");
  return { token };
});

export const revokeApiTokenAction = action(async function revokeApiTokenAction(tokenId: string) {
  const user = await requirePermission("api.tokens");
  await revokeApiToken(user, z.string().min(1).parse(tokenId));
  revalidatePath("/api-tokens");
});
