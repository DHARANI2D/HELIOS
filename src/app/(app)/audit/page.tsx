import { ScrollText } from "lucide-react";
import { ComingSoon } from "@/components/shell/coming-soon";

export default function AuditPage() {
  return (
    <ComingSoon
      icon={ScrollText}
      title="Audit Log"
      description="One hash-chained trail of every write action app-wide, generalized from aegis's audit ledger, lands here next."
    />
  );
}
