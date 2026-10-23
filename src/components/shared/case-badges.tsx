import type { CaseSeverity, CaseSource, CaseStatus } from "@prisma/client";

import { Badge } from "@/components/ui/badge";
import { SEVERITY_BADGE_VARIANT, SEVERITY_LABEL } from "@/lib/severity";
import { CASE_SOURCE_LABEL, CASE_STATUS_LABEL } from "@/lib/cases/labels";

export function SeverityBadge({ severity }: { severity: CaseSeverity }) {
  return <Badge variant={SEVERITY_BADGE_VARIANT[severity]}>{SEVERITY_LABEL[severity]}</Badge>;
}

const STATUS_VARIANT: Record<CaseStatus, "default" | "secondary" | "outline" | "warning" | "success" | "destructive"> = {
  OPEN: "outline",
  TRIAGING: "outline",
  INVESTIGATING: "secondary",
  AWAITING_APPROVAL: "warning",
  CONTAINED: "default",
  RESOLVED: "success",
  FALSE_POSITIVE: "secondary",
};

export function StatusBadge({ status }: { status: CaseStatus }) {
  return <Badge variant={STATUS_VARIANT[status]}>{CASE_STATUS_LABEL[status]}</Badge>;
}

export function SourceBadge({ source }: { source: CaseSource }) {
  return (
    <Badge variant="outline" className="font-normal text-muted-foreground">
      {CASE_SOURCE_LABEL[source]}
    </Badge>
  );
}
