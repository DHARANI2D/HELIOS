import { Mail } from "lucide-react";
import { ComingSoon } from "@/components/shell/coming-soon";

export default function ForensicsPage() {
  return (
    <ComingSoon
      icon={Mail}
      title="Email & File Forensics"
      description="Header/body/attachment analysis and sandbox detonation, ported from desas, land here next — the highest-risk part of the port."
    />
  );
}
