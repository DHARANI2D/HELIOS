"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { requirePermission } from "@/lib/session";
import { action } from "@/lib/action";
import { changeActorOf } from "@/lib/changes/rules";
import { approveChange, rejectChange, withdrawChange } from "@/lib/changes/service";

// Decisions on rule changes (lib/changes). Each one re-checks on the server
// who may decide what; the page only shows the buttons.

function refresh() {
  for (const p of ["/changes", "/rulebook", "/approvals", "/ai", "/tenants"]) revalidatePath(p);
}

const side = z.enum(["client", "helios"]);

export const approveChangeAction = action(async function approveChangeAction(id: string, input: { side: string; note?: string; acknowledged?: boolean }) {
  const user = await requirePermission("rulebook.view");
  if (!input.acknowledged) throw new Error("Confirm you've read the change and approve it taking effect");
  const result = await approveChange(String(id), side.parse(input.side), changeActorOf(user), String(input.note ?? ""));
  refresh();
  return { applied: result.applied };
});

export const rejectChangeAction = action(async function rejectChangeAction(id: string, note: string) {
  const user = await requirePermission("rulebook.view");
  await rejectChange(String(id), changeActorOf(user), String(note ?? "").slice(0, 1000));
  refresh();
});

export const withdrawChangeAction = action(async function withdrawChangeAction(id: string) {
  const user = await requirePermission("rulebook.view");
  await withdrawChange(String(id), changeActorOf(user));
  refresh();
});
