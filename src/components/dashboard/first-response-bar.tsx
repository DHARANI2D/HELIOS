"use client";

import { useChartTokens } from "@/lib/chart-theme";

// Who handled first response over the period: part-to-whole, 3 categorical
// slots, 2px surface gaps, and a legend carrying every count.
export function FirstResponseBar({ autoContained, aiTriaged, analystOnly }: { autoContained: number; aiTriaged: number; analystOnly: number }) {
  const t = useChartTokens();
  const parts = [
    { label: "AI triaged & contained", value: autoContained, color: t.series[0] },
    { label: "AI triaged → analyst", value: aiTriaged, color: t.series[1] },
    { label: "Analyst only", value: analystOnly, color: t.series[2] },
  ];
  const total = parts.reduce((s, p) => s + p.value, 0);
  if (total === 0) return <p className="text-sm text-muted-foreground">No cases in the last 30 days.</p>;
  return (
    <div className="flex flex-col gap-3">
      <div className="flex h-3 gap-[2px] overflow-hidden rounded-full" role="img" aria-label={parts.map((p) => `${p.label}: ${p.value}`).join(", ")}>
        {parts.filter((p) => p.value > 0).map((p) => (
          <div key={p.label} style={{ width: `${(p.value / total) * 100}%`, background: p.color }} title={`${p.label}: ${p.value}`} />
        ))}
      </div>
      <ul className="flex flex-col gap-1.5 text-sm">
        {parts.map((p) => (
          <li key={p.label} className="flex items-center justify-between gap-2">
            <span className="flex items-center gap-2 text-muted-foreground">
              <span className="size-2.5 rounded-full" style={{ background: p.color }} />
              {p.label}
            </span>
            <span className="tabular">
              {p.value} <span className="text-xs text-muted-foreground">({Math.round((p.value / total) * 100)}%)</span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
