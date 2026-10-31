import { db } from "@/lib/db";

// Claims a one-off piece of work (a week's QA sample, say) across
// instances: true for the first caller only.
export async function claimOnce(key: string) {
  const rows = await db.$queryRaw<Array<{ key: string }>>`
    INSERT INTO platform_settings (key, value, "updatedAt") VALUES (${key}, ${JSON.stringify({ at: new Date().toISOString() })}::jsonb, now())
    ON CONFLICT (key) DO NOTHING
    RETURNING key`;
  return rows.length > 0;
}

export async function claimed(key: string) {
  return (await db.platformSetting.count({ where: { key } })) > 0;
}
