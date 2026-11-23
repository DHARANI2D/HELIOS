// Display labels shared by the AI Security pages. Client-safe.

export const VERDICT_VARIANT = { allow: "success", watch: "info", redact: "warning", block: "destructive" } as const;

export const VERDICT_LABEL = { allow: "allowed", watch: "watched", redact: "masked", block: "blocked" } as const;

export const STAGE_LABEL: Record<string, string> = { prompt: "prompt", retrieval: "retrieval", tool_call: "tool call", tool_output: "tool result", output: "answer" };
