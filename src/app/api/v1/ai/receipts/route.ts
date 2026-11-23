import { z } from "zod";

import { handle, json } from "@/lib/api/http";
import { readJson } from "@/lib/aisec/api";
import { receiptKey, verifyReceipt } from "@/lib/aisec/receipts";

// GET  /api/v1/ai/receipts   the public key guard receipts are signed with
// POST /api/v1/ai/receipts   { body, keyId, signature } → { valid, reason }
// Neither needs a token: a receipt proves itself.
export const GET = handle(async () => json(receiptKey()));

const schema = z.object({ body: z.record(z.string(), z.unknown()), keyId: z.string().max(64).optional(), signature: z.string().max(400) });

export const POST = handle(async (request: Request) => {
  const r = schema.parse(await readJson(request, 64 * 1024));
  return json(verifyReceipt(r));
});
