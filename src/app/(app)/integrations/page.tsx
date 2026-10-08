import { Plug } from "lucide-react";

import { requireSession, requireOrgContext } from "@/lib/tenant";
import { listIntegrations } from "@/lib/integrations/service";
import { StatTile } from "@/components/dashboard/stat-tile";
import { IntegrationsTable } from "@/components/integrations/integrations-table";
import { CreateIntegrationDialog } from "@/components/integrations/create-integration-dialog";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default async function IntegrationsPage() {
  const ctx = await requireSession();
  const organizationId = requireOrgContext(ctx);

  const integrations = await listIntegrations({ organizationId });

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatTile label="Integrations" value={integrations.length} icon={Plug} />
        <StatTile
          label="Connected"
          value={integrations.filter((i) => i.status === "CONNECTED").length}
          icon={Plug}
        />
      </div>

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-4">
          <div>
            <CardTitle className="text-base">Integrations</CardTitle>
            <CardDescription>
              Connect your existing security tools — any tool that can send a webhook can point at
              the URL generated here, and its events flow straight into detection. Vendor-specific
              actions (e.g. isolating a host via a specific EDR&apos;s API) aren&apos;t built yet —
              this is the generic ingestion path every connector plugs into.
            </CardDescription>
          </div>
          <CreateIntegrationDialog />
        </CardHeader>
        <CardContent>
          <IntegrationsTable initialData={integrations} />
        </CardContent>
      </Card>
    </div>
  );
}
