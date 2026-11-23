import { ApiError, handle, json } from "@/lib/api/http";
import { guardSchema, readJson, systemFromRequest } from "@/lib/aisec/api";
import { guard } from "@/lib/aisec/service";

// POST /api/v1/ai/guard
//   Authorization: Bearer <the AI system's key, hgs_…>
//   { "stage": "prompt" | "retrieval" | "tool_call" | "tool_output" | "output",
//     "content": "…",                                   prompt, tool_output, output
//     "tool": { "name": "refund_payment", "args": {…} },   tool_call
//     "documents": [{ "id": "…", "text": "…", "access": ["nurse"] }],   retrieval
//     "user": { "id": "end-user id", "roles": ["nurse"], "ip": "…" },
//     "task": "order status", "confirmed": false }
// Answers { decision, action, findings, content?, documents?, withheld?,
// needsConfirmation?, explanation, receipt }. The application does what
// "action" says: allow / watch go ahead (with "content" or "documents" when
// given), redact uses them, block stops.
export const POST = handle(async (request: Request) => {
  const system = await systemFromRequest(request);
  const body = guardSchema.parse(await readJson(request));
  if (body.stage === "tool_call" && !body.tool) throw new ApiError(400, "A tool_call check needs tool.name and tool.args");
  if (body.stage === "retrieval" && !body.documents) throw new ApiError(400, "A retrieval check needs documents");
  if (["prompt", "tool_output", "output"].includes(body.stage) && body.content === undefined) throw new ApiError(400, `A ${body.stage} check needs content`);
  const out = await guard(system, body);
  return json({
    decision: out.decision,
    action: out.enforced,
    mode: system.mode,
    findings: out.findings,
    ...(out.content !== undefined ? { content: out.content } : {}),
    ...(out.documents ? { documents: out.documents, withheld: out.withheld } : {}),
    ...(out.needsConfirmation ? { needsConfirmation: true } : {}),
    explanation: out.explanation,
    receipt: out.receipt,
    caseId: out.caseId,
  });
});
