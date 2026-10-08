"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";

import { listOrganizationsAction } from "@/app/(app)/admin/organizations/actions";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

type OrganizationRow = Awaited<ReturnType<typeof listOrganizationsAction>>[number];

export function OrganizationsTable({ initialData }: { initialData: OrganizationRow[] }) {
  const { data } = useQuery({
    queryKey: ["admin-organizations"],
    queryFn: () => listOrganizationsAction(),
    initialData,
    refetchInterval: 15000,
  });

  if (!data.length) {
    return (
      <p className="py-10 text-center text-sm text-muted-foreground">
        No tenants yet — create one above.
      </p>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Name</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>AI tier</TableHead>
          <TableHead>Users</TableHead>
          <TableHead>Cases</TableHead>
          <TableHead>Created</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.map((org) => (
          <TableRow key={org.id} className="cursor-pointer">
            <TableCell>
              <Link href={`/admin/organizations/${org.id}`} className="font-medium hover:underline">
                {org.name}
              </Link>
              <div className="text-xs text-muted-foreground">{org.slug}</div>
            </TableCell>
            <TableCell>
              <Badge variant={org.status === "ACTIVE" ? "default" : "outline"}>{org.status}</Badge>
            </TableCell>
            <TableCell>{org.aiTier}</TableCell>
            <TableCell>{org._count.users}</TableCell>
            <TableCell>{org._count.cases}</TableCell>
            <TableCell>{new Date(org.createdAt).toLocaleDateString()}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
