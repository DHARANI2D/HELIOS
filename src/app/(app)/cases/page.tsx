import { ShieldAlert } from "lucide-react";
import { ComingSoon } from "@/components/shell/coming-soon";

export default function CasesPage() {
  return (
    <ComingSoon
      icon={ShieldAlert}
      title="Cases & Alerts"
      description="The unified Case/Detection stream and the ported signal-fusion detection engine land here next."
    />
  );
}
