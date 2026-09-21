import Link from "next/link";
import { ShieldAlert, Siren, UserCog, Workflow, Inbox } from "lucide-react";
import type { CaseSeverity } from "@prisma/client";

import { db } from "@/lib/db";
import { SEVERITY_ORDER, SEVERITY_LABEL } from "@/lib/severity";
import { StatTile } from "@/components/dashboard/stat-tile";
import { SeverityBarChart } from "@/components/dashboard/severity-bar-chart";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { NAV_ITEMS } from "@/lib/nav";

async function getOverviewData() {
  const [openCases, criticalCases, activeAgents, pendingApprovals, severityGroups, recentCases] =
    await Promise.all([
      db.case.count({
        where: { status: { notIn: ["RESOLVED", "FALSE_POSITIVE"] } },
      }),
      db.case.count({
        where: {
          severity: "CRITICAL",
          status: { notIn: ["RESOLVED", "FALSE_POSITIVE"] },
        },
      }),
      db.agent.count({ where: { status: "ACTIVE" } }),
      db.playbookExecution.count({
        where: { status: "PENDING_APPROVAL" },
      }),
      db.case.groupBy({
        by: ["severity"],
        _count: { _all: true },
        where: { status: { notIn: ["RESOLVED", "FALSE_POSITIVE"] } },
      }),
      db.case.findMany({
        take: 8,
        orderBy: { createdAt: "desc" },
        select: {
          id: true,
          title: true,
          sourceType: true,
          severity: true,
          status: true,
          createdAt: true,
        },
      }),
    ]);

  const severityCounts = Object.fromEntries(
    SEVERITY_ORDER.map((s) => [s, 0]),
  ) as Record<CaseSeverity, number>;
  for (const group of severityGroups) {
    severityCounts[group.severity] = group._count._all;
  }

  return {
    openCases,
    criticalCases,
    activeAgents,
    pendingApprovals,
    severityCounts,
    recentCases,
  };
}

export default async function OverviewPage() {
  const {
    openCases,
    criticalCases,
    activeAgents,
    pendingApprovals,
    severityCounts,
    recentCases,
  } = await getOverviewData();

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile
          label="Open cases"
          value={openCases}
          icon={ShieldAlert}
        />
        <StatTile
          label="Critical severity"
          value={criticalCases}
          icon={Siren}
          tone={criticalCases > 0 ? "critical" : "default"}
        />
        <StatTile label="Active agents" value={activeAgents} icon={UserCog} />
        <StatTile
          label="Playbooks awaiting approval"
          value={pendingApprovals}
          icon={Workflow}
          tone={pendingApprovals > 0 ? "warning" : "default"}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Open cases by severity</CardTitle>
            <CardDescription>
              Across all four detection sources
            </CardDescription>
          </CardHeader>
          <CardContent>
            <SeverityBarChart counts={severityCounts} />
          </CardContent>
        </Card>

        <Card className="lg:col-span-3">
          <CardHeader>
            <CardTitle>Recent cases</CardTitle>
            <CardDescription>Latest activity across every module</CardDescription>
          </CardHeader>
          <CardContent>
            {recentCases.length === 0 ? (
              <EmptyState />
            ) : (
              <ul className="divide-y">
                {recentCases.map((c) => (
                  <li key={c.id} className="flex items-center justify-between py-2.5">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium">{c.title}</p>
                      <p className="text-xs text-muted-foreground">
                        {c.sourceType.replaceAll("_", " ")} · {c.status}
                      </p>
                    </div>
                    <Badge variant="outline">
                      {SEVERITY_LABEL[c.severity]}
                    </Badge>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Feature areas</CardTitle>
          <CardDescription>
            Every module writes into the same Case/Detection stream shown above
          </CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {NAV_ITEMS.filter((i) => i.href !== "/").map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className="flex items-start gap-3 rounded-lg border p-3 transition-colors hover:bg-accent"
            >
              <item.icon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
              <div>
                <p className="text-sm font-medium">{item.title}</p>
                <p className="text-xs text-muted-foreground">
                  {item.description}
                </p>
              </div>
            </Link>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-10 text-center text-muted-foreground">
      <Inbox className="size-6" />
      <p className="text-sm">No cases yet.</p>
      <p className="text-xs">
        Cases appear here once a detection source (Governance, Investigations,
        Forensics, or Alerts) creates one.
      </p>
    </div>
  );
}
