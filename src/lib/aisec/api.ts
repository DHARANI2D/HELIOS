import { z } from "zod";

import { ApiError } from "@/lib/api/http";
import { STAGES, type Stage } from "@/lib/aisec/policy";
import { systemForKey } from "@/lib/aisec/service";

// Shared by the AI guard and gateway routes: the system's key, a size cap,
// and the guard request's shape.

export const MAX_BODY = 2 * 1024 * 1024;

export async function systemFromRequest(request: Request) {
  const system = await systemForKey(request.headers.get("authorization"));
  if (!system) throw new ApiError(401, "Missing, invalid or revoked AI system key (hgs_…)");
  if (system.status === "paused") throw new ApiError(423, "This AI system is paused in HELIOS");
  return system;
}

export async function readJson(request: Request, max = MAX_BODY): Promise<unknown> {
  const text = await request.text();
  if (text.length > max) throw new ApiError(413, `Body larger than ${Math.round(max / 1024)} KB`);
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError(400, "Body must be JSON");
  }
}

export const guardSchema = z.object({
  stage: z.enum(Object.keys(STAGES) as [Stage, ...Stage[]]),
  content: z.string().max(1_000_000).optional(),
  tool: z.object({ name: z.string().trim().min(1).max(120), args: z.record(z.string(), z.unknown()).default({}) }).optional(),
  documents: z.array(z.object({ id: z.string().min(1).max(200), text: z.string().max(200_000), access: z.array(z.string().max(80)).max(20).optional() })).max(100).optional(),
  user: z.object({ id: z.string().max(200).optional(), roles: z.array(z.string().max(80)).max(30).optional(), ip: z.string().max(64).optional() }).optional(),
  task: z.string().max(120).optional(),
  confirmed: z.boolean().optional(),
  session: z.string().max(200).optional(),
});

export const clientIp = (request: Request) => request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || undefined;
