import { Tags } from "lucide-react";

import { requireSession, requirePlatformRole } from "@/lib/tenant";
import { listPlans } from "@/lib/billing/service";
import { StatTile } from "@/components/dashboard/stat-tile";
import { PlansTable } from "@/components/admin/plans-table";
import { CreatePlanDialog } from "@/components/admin/create-plan-dialog";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default async function PlansPage() {
  const ctx = await requireSession();
  requirePlatformRole(ctx);

  const plans = await listPlans();

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatTile label="Plans in catalog" value={plans.length} icon={Tags} />
        <StatTile label="Active" value={plans.filter((p) => p.active).length} icon={Tags} />
      </div>

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-4">
          <div>
            <CardTitle className="text-base">Plan catalog</CardTitle>
            <CardDescription>
              One row per service × AI tier combination — this is the literal price list customers choose from
            </CardDescription>
          </div>
          <CreatePlanDialog />
        </CardHeader>
        <CardContent>
          <PlansTable initialData={plans} />
        </CardContent>
      </Card>
    </div>
  );
}
