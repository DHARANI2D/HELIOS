import { Crosshair } from "lucide-react";
import { ComingSoon } from "@/components/shell/coming-soon";

export default function MitrePage() {
  return (
    <ComingSoon
      icon={Crosshair}
      title="MITRE ATT&CK Coverage"
      description="A single dashboard aggregating technique coverage across all four detection sources lands here next."
    />
  );
}
