import { Badge } from "@/components/ui/badge";

const STATUS: Record<string, { label: string; variant: "warning" | "success" | "destructive" | "outline" | "soft" | "info" | "secondary" }> = {
  requested: { label: "Waiting for authorisation", variant: "warning" },
  authorised: { label: "Authorised", variant: "info" },
  queued: { label: "Queued", variant: "soft" },
  running: { label: "Running", variant: "secondary" },
  completed: { label: "Report ready", variant: "success" },
  rejected: { label: "Rejected", variant: "outline" },
  cancelled: { label: "Stopped", variant: "outline" },
};

export function TestStatusBadge({ status }: { status: string }) {
  const s = STATUS[status] ?? { label: status, variant: "outline" as const };
  return <Badge variant={s.variant}>{s.label}</Badge>;
}
