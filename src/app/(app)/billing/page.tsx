import { CreditCard } from "lucide-react";

import { requireSession, requireOrgContext } from "@/lib/tenant";
import { getMyBillingAction } from "./actions";
import { StatTile } from "@/components/dashboard/stat-tile";
import { BillingInvoicesTable } from "@/components/billing/billing-invoices-table";
import { RequestChangeForm } from "@/components/billing/request-change-form";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default async function BillingPage() {
  const ctx = await requireSession();
  requireOrgContext(ctx);

  const { organization, subscriptions, invoices } = await getMyBillingAction();
  const outstanding = invoices.filter((i) => i.status === "SENT" || i.status === "OVERDUE");

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatTile label="Active plans" value={subscriptions.length} icon={CreditCard} />
        <StatTile
          label="Outstanding invoices"
          value={outstanding.length}
          icon={CreditCard}
          tone={outstanding.length > 0 ? "warning" : "default"}
        />
        <StatTile label="AI tier" value={organization.aiTier} icon={CreditCard} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Your plans</CardTitle>
          <CardDescription>Services you&apos;re subscribed to and what powers them</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {subscriptions.length === 0 && (
            <p className="text-sm text-muted-foreground">
              No active subscriptions yet — contact your account owner.
            </p>
          )}
          {subscriptions.map((s) => (
            <div key={s.id} className="flex items-center justify-between rounded-md border p-3">
              <div>
                <p className="text-sm font-medium">{s.plan.name}</p>
                <p className="text-xs text-muted-foreground">
                  {s.plan.serviceType.replaceAll("_", " ")} · {s.plan.aiTier} · ${s.plan.priceMonthly}/mo
                </p>
              </div>
              <Badge variant={s.status === "ACTIVE" ? "default" : "outline"}>{s.status}</Badge>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Invoices</CardTitle>
          <CardDescription>Billed monthly — contact your account owner about payment</CardDescription>
        </CardHeader>
        <CardContent>
          <BillingInvoicesTable invoices={invoices} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Request a change</CardTitle>
          <CardDescription>
            No self-service checkout yet — this notifies your account owner directly
          </CardDescription>
        </CardHeader>
        <CardContent>
          <RequestChangeForm />
        </CardContent>
      </Card>
    </div>
  );
}
