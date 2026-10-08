import { Building2 } from "lucide-react";

import { requireSession, requirePlatformRole } from "@/lib/tenant";
import { listOrganizations } from "@/lib/billing/service";
import { StatTile } from "@/components/dashboard/stat-tile";
import { OrganizationsTable } from "@/components/admin/organizations-table";
import { CreateOrganizationDialog } from "@/components/admin/create-organization-dialog";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";

export default async function OrganizationsPage() {
  const ctx = await requireSession();
  requirePlatformRole(ctx);

  const organizations = await listOrganizations();

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatTile label="Tenants" value={organizations.length} icon={Building2} />
        <StatTile
          label="Active"
          value={organizations.filter((o) => o.status === "ACTIVE").length}
          icon={Building2}
        />
        <StatTile
          label="Trial"
          value={organizations.filter((o) => o.status === "TRIAL").length}
          icon={Building2}
        />
      </div>

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-4">
          <div>
            <CardTitle className="text-base">Organizations</CardTitle>
            <CardDescription>
              Every tenant on the platform — admin-provisioned only, no public signup
            </CardDescription>
          </div>
          <CreateOrganizationDialog />
        </CardHeader>
        <CardContent>
          <OrganizationsTable initialData={organizations} />
        </CardContent>
      </Card>
    </div>
  );
}
