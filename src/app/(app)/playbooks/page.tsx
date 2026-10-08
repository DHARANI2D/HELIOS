import { Workflow, PlayCircle, Hourglass } from "lucide-react";

import { db } from "@/lib/db";
import { requireSession, tenantWhere, type TenantContext } from "@/lib/tenant";
import { StatTile } from "@/components/dashboard/stat-tile";
import { CreatePlaybookForm } from "@/components/playbooks/create-playbook-form";
import { PlaybookList } from "@/components/playbooks/playbook-list";
import { PendingApprovals } from "@/components/playbooks/pending-approvals";
import { ExecutionHistory } from "@/components/playbooks/execution-history";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

async function getPlaybookStats(ctx: TenantContext) {
  const scope = tenantWhere(ctx);
  const [total, executions, pending] = await Promise.all([
    db.playbook.count({ where: scope }),
    db.playbookExecution.count({ where: { status: "SUCCEEDED", case: scope } }),
    db.playbookExecution.count({ where: { status: "PENDING_APPROVAL", case: scope } }),
  ]);
  return { total, executions, pending };
}

export default async function PlaybooksPage() {
  const ctx = await requireSession();
  const stats = await getPlaybookStats(ctx);

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatTile label="Playbooks" value={stats.total} icon={Workflow} />
        <StatTile label="Successful executions" value={stats.executions} icon={PlayCircle} />
        <StatTile
          label="Pending approvals"
          value={stats.pending}
          icon={Hourglass}
          tone={stats.pending > 0 ? "warning" : "default"}
        />
      </div>

      <PendingApprovals />
      <CreatePlaybookForm />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Playbooks</CardTitle>
        </CardHeader>
        <CardContent>
          <PlaybookList />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Execution history</CardTitle>
          <CardDescription>Every playbook run across all four modules</CardDescription>
        </CardHeader>
        <CardContent>
          <ExecutionHistory />
        </CardContent>
      </Card>
    </div>
  );
}
