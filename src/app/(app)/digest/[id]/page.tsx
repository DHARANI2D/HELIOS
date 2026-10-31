import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import type { DigestSummary } from "@/lib/operations/digest";
import { DigestView } from "@/components/operations/digest-view";
import { Button } from "@/components/ui/button";

// One daily digest: a client's own (its admins and viewers), or any of them
// and the SOC's (staff who can see operations).
export default async function DigestPage({ params }: PageProps<"/digest/[id]">) {
  const { id } = await params;
  const user = await pageGuard();
  const run = await db.digestRun.findUnique({ where: { id } });
  const allowed = run && (user.isClient ? can(user, "reports.view") && run.tenantId === user.tenantId : can(user, "operations.view"));
  if (!run || !allowed) notFound();
  return (
    <div className="flex flex-col gap-4">
      <Button variant="ghost" size="sm" asChild className="-ml-2 self-start"><Link href="/digest"><ArrowLeft /> Daily digests</Link></Button>
      <DigestView d={run.summary as unknown as DigestSummary} />
    </div>
  );
}
