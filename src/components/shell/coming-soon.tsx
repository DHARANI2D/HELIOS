import type { LucideIcon } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";

interface ComingSoonProps {
  icon: LucideIcon;
  title: string;
  description: string;
}

export function ComingSoon({ icon: Icon, title, description }: ComingSoonProps) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-3 py-20 text-center">
        <div className="flex size-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <Icon className="size-5" />
        </div>
        <div>
          <p className="text-sm font-medium">{title}</p>
          <p className="mt-1 max-w-sm text-sm text-muted-foreground">
            {description}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
