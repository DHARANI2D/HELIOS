import type { LucideIcon } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface StatTileProps {
  label: string;
  value: string | number;
  icon: LucideIcon;
  tone?: "default" | "critical" | "warning";
}

export function StatTile({
  label,
  value,
  icon: Icon,
  tone = "default",
}: StatTileProps) {
  return (
    <Card>
      <CardContent className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm text-muted-foreground">{label}</p>
          <p
            className={cn(
              "mt-1 text-2xl font-semibold tabular-nums",
              tone === "critical" && "text-destructive",
              tone === "warning" && "text-warning-foreground",
            )}
          >
            {value}
          </p>
        </div>
        <div
          className={cn(
            "flex size-9 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground",
            tone === "critical" && "bg-destructive/10 text-destructive",
            tone === "warning" && "bg-warning/20 text-warning-foreground",
          )}
        >
          <Icon className="size-4" />
        </div>
      </CardContent>
    </Card>
  );
}
