import { notFound } from "next/navigation";

import { requireSession, requirePlatformRole } from "@/lib/tenant";
import { getOrganizationDetail, listPlans, getBillingChangeRequests } from "@/lib/billing/service";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { OrgSettingsForm } from "@/components/admin/org-settings-form";
import { CreateSubscriptionForm } from "@/components/admin/create-subscription-form";
import { CreateInvoiceForm } from "@/components/admin/create-invoice-form";

export default async function OrganizationDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const ctx = await requireSession();
  requirePlatformRole(ctx);

  const { id } = await params;
  const [org, plans, billingRequests] = await Promise.all([
    getOrganizationDetail(id),
    listPlans(),
    getBillingChangeRequests(id),
  ]);
  if (!org) notFound();

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">{org.name}</h2>
          <p className="text-sm text-muted-foreground">{org.slug}</p>
        </div>
        <Badge variant={org.status === "ACTIVE" ? "default" : "outline"}>{org.status}</Badge>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Settings</CardTitle>
            <CardDescription>AI tier, status, and self-hosted endpoint</CardDescription>
          </CardHeader>
          <CardContent>
            <OrgSettingsForm
              organizationId={org.id}
              aiTier={org.aiTier}
              status={org.status}
              selfHostedOllamaUrl={org.selfHostedOllamaUrl}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Users</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Email</TableHead>
                  <TableHead>Role</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {org.users.map((u) => (
                  <TableRow key={u.id}>
                    <TableCell>{u.name}</TableCell>
                    <TableCell>{u.email}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{u.role}</Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {billingRequests.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Billing change requests</CardTitle>
            <CardDescription>Sent by this tenant&apos;s org admins from their Billing page</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {billingRequests.map((r) => (
              <div key={r.id} className="rounded-md border p-2 text-sm">
                <p>{(r.detail as { message?: string } | null)?.message}</p>
                <p className="text-xs text-muted-foreground">
                  {r.actor?.name ?? r.actor?.email} · {new Date(r.createdAt).toLocaleString()}
                </p>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Subscriptions</CardTitle>
            <CardDescription>Which plans this tenant is on</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <CreateSubscriptionForm organizationId={org.id} plans={plans.filter((p) => p.active)} />
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Plan</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Renews</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {org.subscriptions.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>
                      {s.plan.name}
                      <div className="text-xs text-muted-foreground">
                        {s.plan.serviceType.replaceAll("_", " ")} · {s.plan.aiTier}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={s.status === "ACTIVE" ? "default" : "outline"}>{s.status}</Badge>
                    </TableCell>
                    <TableCell>{new Date(s.currentPeriodEnd).toLocaleDateString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Invoices</CardTitle>
            <CardDescription>No live payment processor — mark paid manually for now</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <CreateInvoiceForm
              organizationId={org.id}
              subscriptions={org.subscriptions.map((s) => ({ id: s.id, label: s.plan.name }))}
            />
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Number</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Amount</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {org.invoices.map((inv) => (
                  <TableRow key={inv.id}>
                    <TableCell>{inv.number}</TableCell>
                    <TableCell>
                      <Badge variant={inv.status === "PAID" ? "default" : "outline"}>{inv.status}</Badge>
                    </TableCell>
                    <TableCell>
                      {inv.currency} {inv.totalAmount.toString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
