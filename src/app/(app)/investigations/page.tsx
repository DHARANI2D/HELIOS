import { Search } from "lucide-react";
import { ComingSoon } from "@/components/shell/coming-soon";

export default function InvestigationsPage() {
  return (
    <ComingSoon
      icon={Search}
      title="Investigations"
      description="The LangGraph.js triage/RCA/QA/report swarm and entity-graph view, ported from asip, land here next."
    />
  );
}
