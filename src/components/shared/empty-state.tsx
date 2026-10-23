import type { LucideIcon } from "lucide-react";

export function EmptyState({
  icon: Icon,
  title,
  description,
  children,
}: {
  icon: LucideIcon;
  title: string;
  description?: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-center text-muted-foreground">
      <Icon className="size-6" />
      <p className="text-sm font-medium text-foreground">{title}</p>
      {description && <p className="max-w-md text-xs">{description}</p>}
      {children}
    </div>
  );
}
