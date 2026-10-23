import { Badge } from "@/components/ui/badge";
import type { IndicatorVerdict } from "@/lib/threat-intel/local-intel";

const VARIANT: Record<IndicatorVerdict, "destructive" | "warning" | "secondary" | "success" | "outline"> = {
  malicious: "destructive",
  suspicious: "warning",
  low: "secondary",
  clean: "success",
  unknown: "outline",
};

export function VerdictBadge({ verdict }: { verdict: IndicatorVerdict }) {
  return <Badge variant={VARIANT[verdict]} className="capitalize">{verdict}</Badge>;
}
