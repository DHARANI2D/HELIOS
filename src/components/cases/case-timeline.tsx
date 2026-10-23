import type { TimelineEntry } from "@prisma/client";

import { formatDateTime } from "@/lib/format";
import { cn } from "@/lib/utils";

// Timeline entry actions are namespaced ("detection.fired", "playbook.block_ip",
// "analyst.note", "endpoint.process_start") — the prefix picks the marker tone.
function tone(action: string) {
  if (action.startsWith("detection.")) return "bg-destructive";
  if (action.startsWith("playbook.")) return "bg-primary";
  if (action.startsWith("analyst.") || action.startsWith("case.")) return "bg-warning";
  return "bg-muted-foreground/40";
}

export function CaseTimeline({ entries }: { entries: TimelineEntry[] }) {
  if (entries.length === 0) {
    return <p className="py-6 text-center text-sm text-muted-foreground">No timeline entries yet.</p>;
  }
  return (
    <ol className="relative ml-1.5 border-l">
      {entries.map((entry) => (
        <li key={entry.id} className="mb-4 ml-4 last:mb-0">
          <span className={cn("absolute -left-[5px] mt-1.5 size-2.5 rounded-full ring-2 ring-background", tone(entry.action))} />
          <div className="flex flex-wrap items-baseline gap-x-2 text-xs text-muted-foreground">
            <span className="tabular-nums">{formatDateTime(entry.occurredAt)}</span>
            <span className="font-mono">{entry.action}</span>
            {entry.actor && <span>· {entry.actor}</span>}
          </div>
          {entry.detail && <p className="mt-0.5 text-sm whitespace-pre-wrap break-words">{entry.detail}</p>}
        </li>
      ))}
    </ol>
  );
}
