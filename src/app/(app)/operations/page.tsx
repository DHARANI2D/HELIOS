import Link from "next/link";
import { BellRing, ClipboardCheck, PhoneCall, UserRoundCheck } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can, isClientRole, roleLabel } from "@/lib/rbac";
import { getSetting } from "@/lib/settings";
import { formatDateTime, formatRelative } from "@/lib/format";
import { ACTION_LABEL } from "@/lib/response/labels";
import { gaps } from "@/lib/operations/rota";
import { handoffSummary, handoffText, onCallNow } from "@/lib/operations/paging";
import { qaStats } from "@/lib/operations/qa";
import { AcknowledgePage, DeleteShift, OperationsSettingsForm, OverrideForm, PageOnCall, RotaForm, type StaffOption } from "@/components/operations/oncall-controls";
import { StatTile } from "@/components/dashboard/stat-tile";
import { TestBadge } from "@/components/shared/test-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const DAY = 86_400_000;
const LEVEL = ["Primary", "Backup", "SOC managers"];

// SOC operations: who is on call and the pages they get, the weekly QA of
// what the AI did on its own, and the daily digests.
export default async function OperationsPage({ searchParams }: PageProps<"/operations">) {
  const user = await pageGuard("operations.view");
  const canManage = can(user, "operations.manage");
  const highlight = (await searchParams).page;
  const now = new Date();
  const [settings, on, shifts, pages, staffRows, stats, pending, digests, handoff] = await Promise.all([
    getSetting("operations"),
    onCallNow(now),
    db.onCallShift.findMany({ where: { endsAt: { gt: now }, startsAt: { lt: new Date(now.getTime() + 14 * DAY) } }, orderBy: [{ startsAt: "asc" }, { role: "asc" }], include: { user: { select: { name: true, email: true, phone: true } } }, take: 200 }),
    db.onCallPage.findMany({ orderBy: { createdAt: "desc" }, take: 25 }),
    db.user.findMany({ where: { active: true, tenantId: null }, select: { id: true, name: true, email: true, role: true, phone: true }, orderBy: { name: "asc" } }),
    qaStats(6, now),
    db.qaReview.findMany({ where: { status: "PENDING" }, orderBy: [{ weight: "desc" }, { createdAt: "asc" }], take: 50, include: { case: { select: { title: true, severity: true, tenant: { select: { name: true, isTest: true } } } } } }),
    db.digestRun.findMany({ where: { recipients: { gt: 0 } }, orderBy: { createdAt: "desc" }, take: 12 }),
    handoffSummary(now),
  ]);
  const staff: StaffOption[] = staffRows.filter((u) => !isClientRole(u.role) && !["AUDITOR", "SALES"].includes(u.role)).map((u) => ({ id: u.id, name: u.name ?? u.email, role: roleLabel(u.role), phone: !!u.phone }));
  const nameOf = new Map(staffRows.map((u) => [u.id, u.name ?? u.email]));
  const tenantNames = new Map((await db.tenant.findMany({ where: { id: { in: digests.map((d) => d.tenantId).filter((x): x is string => !!x) } }, select: { id: true, name: true } })).map((t) => [t.id, t.name]));
  const holes = gaps(shifts, now, new Date(now.getTime() + 7 * DAY), "primary");
  const unanswered = pages.filter((p) => !p.ackAt);
  const mine = pending.filter((p) => p.reviewerId === user.id);
  const thisWeek = stats.weeks[0];
  const person = (u: { name: string | null; email: string; phone: string | null }) => `${u.name ?? u.email}${u.phone ? "" : " (no phone number)"}`;

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
        <StatTile label="On call now" value={on.primary ? on.primary.user.name ?? on.primary.user.email : "Nobody"} icon={PhoneCall} tone={on.primary ? "default" : "critical"} hint={on.primary ? `until ${formatDateTime(on.primary.endsAt)}` : "Pages go to the backup or the SOC managers"} />
        <StatTile label="Backup" value={on.backup ? on.backup.user.name ?? on.backup.user.email : "Nobody"} icon={UserRoundCheck} tone={on.backup ? "default" : "warning"} />
        <StatTile label="Unanswered pages" value={unanswered.length} icon={BellRing} tone={unanswered.length ? "critical" : "default"} />
        <StatTile label="QA waiting" value={pending.length} icon={ClipboardCheck} tone={pending.length ? "warning" : "default"} hint={mine.length ? `${mine.length} assigned to you` : thisWeek ? `${thisWeek.reviewed} of ${thisWeek.sampled} reviewed for ${thisWeek.week}` : undefined} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Pages</CardTitle>
          <CardDescription>
            Open cases at {settings.pageSeverity.toLowerCase()}{settings.pageSeverity === "CRITICAL" ? "" : " and above"} that nobody has acknowledged page the primary on its own; so does a tripped circuit breaker, and anyone can page from a case. Unanswered after {settings.ackMinutes} minutes, the backup is paged, then the SOC managers. Pages go in the app and by SMS and email, whatever the person&apos;s alert choices.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {pages.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Raised</TableHead>
                  <TableHead>About</TableHead>
                  <TableHead>Reached</TableHead>
                  <TableHead>Answered</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pages.map((p) => (
                  <TableRow key={p.id} className={p.id === highlight ? "bg-primary/5" : undefined}>
                    <TableCell className="text-xs tabular">{formatRelative(p.createdAt, now)}</TableCell>
                    <TableCell className="max-w-md whitespace-normal text-xs">
                      {p.caseId ? <Link href={`/cases/${p.caseId}`} className="font-medium hover:underline">{p.title}</Link> : <span className="font-medium">{p.title}</span>}
                      {p.body && <p className="text-muted-foreground">{p.body}</p>}
                    </TableCell>
                    <TableCell className="text-xs">{LEVEL[p.level]}: {p.pagedIds.map((id) => nameOf.get(id) ?? "someone").join(", ") || "nobody"}</TableCell>
                    <TableCell className="text-xs">{p.ackAt ? <span className="text-muted-foreground">{p.ackByName} · {formatRelative(p.ackAt, now)}</span> : <AcknowledgePage id={p.id} />}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {can(user, "cases.escalate") && (
            <div className="max-w-xl">
              <p className="mb-1 text-xs text-muted-foreground">Page whoever is on call about something that isn&apos;t a case (to page about a case, use the button on the case):</p>
              <PageOnCall />
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Rota</CardTitle>
          <CardDescription>The next two weeks, in UTC. At the start of each shift, the person coming on gets a handoff: what&apos;s open and what&apos;s due.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {holes.length > 0 && (
            <p className="text-xs text-destructive">
              Nobody is primary on call for {holes.slice(0, 4).map((g) => `${formatDateTime(g.from)} → ${formatDateTime(g.to)}`).join("; ")}{holes.length > 4 ? ` and ${holes.length - 4} more stretches` : ""} in the next 7 days.
            </p>
          )}
          {shifts.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>From</TableHead>
                  <TableHead>Until</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Who</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {shifts.map((s) => {
                  const live = s.startsAt <= now && s.endsAt > now;
                  return (
                    <TableRow key={s.id} className={live ? "bg-primary/5" : undefined}>
                      <TableCell className="text-xs tabular">{formatDateTime(s.startsAt)}</TableCell>
                      <TableCell className="text-xs tabular">{formatDateTime(s.endsAt)}</TableCell>
                      <TableCell className="text-xs">{s.role === "primary" ? "Primary" : "Backup"}{s.override && <Badge variant="soft" className="ml-1">cover</Badge>}</TableCell>
                      <TableCell className="text-xs">{person(s.user)}{s.note && <span className="block text-muted-foreground">{s.note}</span>}</TableCell>
                      <TableCell className="text-right">{canManage && <DeleteShift id={s.id} />}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          ) : (
            <p className="text-sm text-muted-foreground">Nobody is on the rota. Until someone is, pages go straight to the SOC managers.</p>
          )}
          {canManage && (
            <>
              <div className="rounded-md border p-3"><p className="mb-2 text-sm font-medium">Generate a rotation</p><RotaForm staff={staff} /></div>
              <div className="rounded-md border p-3"><p className="mb-2 text-sm font-medium">Add cover (a swap, leave, sickness)</p><OverrideForm staff={staff} /></div>
            </>
          )}
          <details className="text-xs">
            <summary className="cursor-pointer text-muted-foreground">What a handoff says right now</summary>
            <pre className="mt-1 whitespace-pre-wrap rounded bg-muted p-2">{handoffText(handoff)}</pre>
          </details>
        </CardContent>
      </Card>

      <Card id="qa" className="scroll-mt-20">
        <CardHeader>
          <CardTitle className="text-base">QA of what the AI did on its own</CardTitle>
          <CardDescription>
            Each Monday, {settings.qaSharePct}% of each client&apos;s cases from the week before where the AI ran actions without a person, or called a case benign (at least {settings.qaMinPerClient} a client), go to a reviewer other than the analyst who closed the case. The draw favours critical and high severity, new detection rules and critical assets. A reviewer&apos;s &ldquo;shouldn&apos;t have run&rdquo; counts as a wrong containment on the autonomy ladder that week. Reviews are done on the case.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {stats.weeks.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Week of</TableHead>
                  <TableHead>Sampled</TableHead>
                  <TableHead>Reviewed</TableHead>
                  <TableHead>Right</TableHead>
                  <TableHead>Partly</TableHead>
                  <TableHead>Wrong</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {stats.weeks.map((w) => (
                  <TableRow key={w.week}>
                    <TableCell className="text-xs tabular">{w.week}</TableCell>
                    <TableCell className="text-xs tabular">{w.sampled}</TableCell>
                    <TableCell className="text-xs tabular">{w.reviewed}</TableCell>
                    <TableCell className="text-xs tabular">{w.agree}</TableCell>
                    <TableCell className="text-xs tabular">{w.partly}</TableCell>
                    <TableCell className={`text-xs tabular ${w.disagree ? "text-destructive" : ""}`}>{w.disagree}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {stats.wrongByAction.length > 0 && <p className="text-xs">Actions judged wrong in these weeks: {stats.wrongByAction.map((w) => `${ACTION_LABEL[w.actionType]} ${w.count}`).join(", ")}.</p>}
          {pending.length > 0 ? (
            <ul className="divide-y text-xs">
              {[...mine, ...pending.filter((p) => p.reviewerId !== user.id)].map((r) => (
                <li key={r.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
                  <span>
                    <Link href={`/cases/${r.caseId}#qa`} className="font-medium hover:underline">{r.case.title}</Link>
                    <span className="text-muted-foreground"> · {r.case.tenant?.name ?? "Internal"}</span>{r.case.tenant?.isTest && <TestBadge className="ml-1" />}
                    <span className="block text-muted-foreground">{r.reasons.join(", ")}</span>
                  </span>
                  <span className="text-muted-foreground">{r.reviewerId === user.id ? <Badge variant="warning">yours</Badge> : r.reviewerId ? nameOf.get(r.reviewerId) : "unassigned"} · week of {r.week.toISOString().slice(0, 10)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted-foreground">Nothing waiting for review.</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Daily digests</CardTitle>
          <CardDescription>
            At the top of the autonomy ladder the AI acts without telling anyone at the time; the digest is where it reports. Each client&apos;s admins get theirs, and the SOC managers one across every client, at {String(settings.digestHour).padStart(2, "0")}:00 {settings.timeZone}, in the app and by email for those who chose it. A day with nothing to say sends nothing.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {digests.length > 0 ? (
            <ul className="divide-y text-xs">
              {digests.map((d) => (
                <li key={d.id} className="flex items-center justify-between py-1.5">
                  <Link href={`/digest/${d.id}`} className="hover:underline">{d.tenantId ? tenantNames.get(d.tenantId) ?? "A client" : "All clients (SOC)"} · {d.day.toISOString().slice(0, 10)}</Link>
                  <span className="text-muted-foreground">{d.recipients} recipient{d.recipients === 1 ? "" : "s"}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted-foreground">No digest sent yet.</p>
          )}
          {canManage && <div className="rounded-md border p-3"><p className="mb-2 text-sm font-medium">Settings</p><OperationsSettingsForm value={settings} /></div>}
        </CardContent>
      </Card>
    </div>
  );
}
