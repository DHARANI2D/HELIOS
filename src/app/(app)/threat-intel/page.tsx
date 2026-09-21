import { Globe2 } from "lucide-react";
import { ComingSoon } from "@/components/shell/coming-soon";

export default function ThreatIntelPage() {
  return (
    <ComingSoon
      icon={Globe2}
      title="Threat Intelligence"
      description="The shared VirusTotal/AbuseIPDB/MxToolbox lookup service and IOC cache, used by every other module, lands here next."
    />
  );
}
