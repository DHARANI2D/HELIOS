"use server";

import { revalidatePath } from "next/cache";

import { requireSession, requirePlatformRole } from "@/lib/tenant";
import { listInvoices, setInvoiceStatus } from "@/lib/billing/service";
import type { InvoiceStatus } from "@prisma/client";

export async function listAllInvoicesAction() {
  const ctx = await requireSession();
  requirePlatformRole(ctx);
  return listInvoices();
}

export async function setInvoiceStatusAction(id: string, status: InvoiceStatus) {
  const ctx = await requireSession();
  requirePlatformRole(ctx);
  await setInvoiceStatus(id, status, {}, ctx.userId);
  revalidatePath("/admin/billing");
}
