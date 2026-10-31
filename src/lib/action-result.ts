// What a server action returns: its value, or the reason it was refused.
// Shared by the server wrapper (`lib/action.ts`) and the client.

export type ActionResult<T> = { ok: true; value: T } | { ok: false; error: string };

// On the client: the action's value, or an Error with its message, so a
// mutation's onError shows the reason.
export async function unwrap<T>(result: Promise<ActionResult<T>>): Promise<T> {
  const r = await result;
  if (!r.ok) throw new Error(r.error);
  return r.value;
}
