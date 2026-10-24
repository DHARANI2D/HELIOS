import { FlaskConical } from "lucide-react";

import { Badge } from "@/components/ui/badge";

// Marks a test client (or a record that belongs to one) wherever it shows.
export function TestBadge({ className }: { className?: string }) {
  return (
    <Badge variant="warning" className={className} title="Test client — holds test data only">
      <FlaskConical />
      test
    </Badge>
  );
}
