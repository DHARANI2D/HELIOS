import { ApiError, handle, json } from "@/lib/api/http";
import { clientIp, readJson, systemFromRequest } from "@/lib/aisec/api";
import { GatewayError, gatewayChat } from "@/lib/aisec/gateway";

// POST /api/v1/ai/gateway/chat/completions
//   Authorization: Bearer <the AI system's key, hgs_…>
// The OpenAI chat-completions request and answer, through HELIOS: point an
// OpenAI-compatible SDK's base URL at https://<helios>/api/v1/ai/gateway and
// use the system's key as the API key. The answer carries a "helios" field
// with each check's decision and receipt.
export const POST = handle(async (request: Request) => {
  const system = await systemFromRequest(request);
  const body = await readJson(request, 8 * 1024 * 1024);
  try {
    const r = await gatewayChat(system, body, { user: { ip: clientIp(request) } });
    const res = json(r.body, r.status);
    res.headers.set("x-helios-decision", r.decision);
    res.headers.set("x-helios-receipts", r.receipts.join(","));
    return res;
  } catch (err) {
    if (err instanceof GatewayError) throw new ApiError(err.status, err.message);
    throw err;
  }
});
