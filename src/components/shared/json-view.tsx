import { cn } from "@/lib/utils";

export function JsonView({ value, className }: { value: unknown; className?: string }) {
  return (
    <pre
      className={cn(
        "max-h-72 overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all",
        className,
      )}
    >
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}
