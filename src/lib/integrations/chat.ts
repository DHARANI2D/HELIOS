import { db } from "@/lib/db";
import { readSecrets } from "@/lib/integrations/dispatch";

// Posts to the client's (or the SOC's own) Slack / Teams channel through the
// incoming webhook stored on a chat integration; falls back to
// SLACK_WEBHOOK_URL for the SOC's own channel.

export async function dispatchChatMessage(tenantId: string | null, text: string): Promise<{ sent: boolean; message: string }> {
  const chat = await db.integration.findFirst({
    where: { category: "chatops", enabled: true, OR: [{ tenantId }, { tenantId: null }] },
    orderBy: [{ tenantId: { sort: "desc", nulls: "last" } }, { createdAt: "asc" }],
  });
  const webhook = chat ? readSecrets(chat.secretCipher).chatWebhookUrl : process.env.SLACK_WEBHOOK_URL;
  if (!webhook) return { sent: false, message: "No chat channel connected — recorded only (add Slack or Teams under Tools & Integrations)" };
  try {
    const res = await fetch(webhook, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return { sent: false, message: `Chat webhook returned HTTP ${res.status}` };
    return { sent: true, message: `Posted to ${chat?.name ?? "the SOC channel"}` };
  } catch (err) {
    return { sent: false, message: `Chat webhook unreachable: ${err instanceof Error ? err.message : String(err)}` };
  }
}
