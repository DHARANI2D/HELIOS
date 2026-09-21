import { Workflow } from "lucide-react";
import { ComingSoon } from "@/components/shell/coming-soon";

export default function PlaybooksPage() {
  return (
    <ComingSoon
      icon={Workflow}
      title="Response Playbooks"
      description="Playbook creation, execution history, and approvals, generalized to trigger from any case type, land here next."
    />
  );
}
