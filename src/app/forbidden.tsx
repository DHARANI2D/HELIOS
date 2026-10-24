import Link from "next/link";
import { ShieldOff } from "lucide-react";

import { Button } from "@/components/ui/button";

export default function Forbidden() {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-3 text-center">
      <div className="flex size-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
        <ShieldOff className="size-5" />
      </div>
      <h2 className="text-lg font-semibold">Your role can&apos;t open this page</h2>
      <p className="max-w-sm text-sm text-muted-foreground">
        Access in HELIOS is role-based. Ask a platform admin if you need this permission — every role and what it can see is listed under Team &amp; Roles.
      </p>
      <Button asChild variant="outline" size="sm">
        <Link href="/">Back to overview</Link>
      </Button>
    </div>
  );
}
