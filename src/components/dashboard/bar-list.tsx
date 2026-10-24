import Link from "next/link";

// Single-series magnitude bars (one hue, value at the tip). Text stays in
// ink tokens; the bar carries the magnitude.
export function BarList({ items, emptyText = "Nothing here.", unit }: { items: Array<{ label: string; value: number; href?: string }>; emptyText?: string; unit?: string }) {
  if (items.length === 0) return <p className="text-sm text-muted-foreground">{emptyText}</p>;
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <ul className="flex flex-col gap-2">
      {items.map((i) => (
        <li key={i.label} className="grid grid-cols-[minmax(6rem,10rem)_1fr_2.5rem] items-center gap-3 text-sm">
          {i.href ? (
            <Link href={i.href} className="truncate hover:underline" title={i.label}>{i.label}</Link>
          ) : (
            <span className="truncate" title={i.label}>{i.label}</span>
          )}
          <div className="h-2 rounded-full bg-muted">
            <div className="h-full rounded-r-[4px] rounded-l-full bg-primary" style={{ width: `${Math.max(2, (i.value / max) * 100)}%` }} />
          </div>
          <span className="text-right tabular text-muted-foreground">
            {i.value}
            {unit ?? ""}
          </span>
        </li>
      ))}
    </ul>
  );
}
