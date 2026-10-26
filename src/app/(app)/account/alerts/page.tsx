import { BellRing } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { formatDateTime } from "@/lib/format";
import { channelStatus } from "@/lib/alerts/send";
import { ALERT_CHANNELS, groupsFromPrefs, parsePrefs, type AlertChannel } from "@/lib/alerts/kinds";
import { AlertPrefsForm } from "@/components/account/alert-prefs";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const STATUS_VARIANT = { PENDING: "outline", SENT: "success", FAILED: "destructive", SKIPPED: "secondary" } as const;

export default async function AlertsPage() {
  const user = await pageGuard("dashboard.view");
  const [me, ready, recent] = await Promise.all([
    db.user.findUniqueOrThrow({ where: { id: user.id }, select: { email: true, phone: true, alertPrefs: true } }),
    channelStatus(),
    db.alertDelivery.findMany({ where: { userId: user.id }, orderBy: { createdAt: "desc" }, take: 15 }),
  ]);
  return (
    <div className="flex max-w-4xl flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><BellRing className="size-4" /> My alerts</CardTitle>
          <CardDescription>
            Everything shows in HELIOS under the bell. Pick what should also reach you by email, SMS or WhatsApp — approvals and regulatory deadlines are the ones that can&apos;t wait. At most a set number go out per hour; the rest stay in the app.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AlertPrefsForm email={me.email} phone={me.phone ?? ""} groups={groupsFromPrefs(parsePrefs(me.alertPrefs))} ready={ready} />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent alerts sent to me</CardTitle>
        </CardHeader>
        <CardContent>
          {recent.length === 0 ? (
            <p className="text-sm text-muted-foreground">None yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead>Channel</TableHead>
                  <TableHead>Alert</TableHead>
                  <TableHead>Outcome</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recent.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell className="text-xs tabular">{formatDateTime(d.createdAt)}</TableCell>
                    <TableCell className="text-xs">{ALERT_CHANNELS[d.channel as AlertChannel] ?? d.channel}</TableCell>
                    <TableCell className="max-w-80 truncate text-xs">{d.subject}</TableCell>
                    <TableCell className="text-xs whitespace-normal"><Badge variant={STATUS_VARIANT[d.status]}>{d.status.toLowerCase()}</Badge> {d.lastError && <span className="text-muted-foreground">{d.lastError}</span>}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
