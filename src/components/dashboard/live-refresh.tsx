"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { RefreshCw } from "lucide-react";

// Re-renders the server dashboard on an interval while the tab is visible.
export function LiveRefresh({ seconds = 30 }: { seconds?: number }) {
  const router = useRouter();
  const [paused, setPaused] = React.useState(false);
  React.useEffect(() => {
    if (paused) return;
    const id = setInterval(() => {
      if (document.visibilityState === "visible") router.refresh();
    }, seconds * 1000);
    return () => clearInterval(id);
  }, [router, seconds, paused]);
  return (
    <button type="button" onClick={() => setPaused((p) => !p)} className="no-print flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs text-muted-foreground hover:bg-accent" title={paused ? "Resume live updates" : "Pause live updates"}>
      <span className={paused ? "size-1.5 rounded-full bg-muted-foreground" : "size-1.5 animate-pulse rounded-full bg-success"} />
      {paused ? "Paused" : `Live · ${seconds}s`}
      <RefreshCw className="size-3" />
    </button>
  );
}
