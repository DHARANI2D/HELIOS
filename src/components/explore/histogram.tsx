"use client";

import ReactECharts from "echarts-for-react";

import { baseOption, compact, useChartTokens } from "@/lib/chart-theme";

// Events over the window, one bar per time bucket, in the accent hue.
// Clicking a bar narrows the search to that bucket.
export function Histogram({ bars, bucketSeconds, from, to, onPick }: { bars: Array<{ t: string; n: number }>; bucketSeconds: number; from: string; to: string; onPick: (from: string, to: string) => void }) {
  const t = useChartTokens();
  // Every bucket in the window, empty ones included, so gaps show as gaps.
  const step = bucketSeconds * 1000;
  const start = new Date(from).getTime();
  const counts = new Map(bars.map((b) => [new Date(b.t).getTime(), b.n]));
  const first = bars.length ? Math.min(start, ...[...counts.keys()]) : start;
  const slots: Array<{ at: number; n: number }> = [];
  for (let at = first; at <= new Date(to).getTime() && slots.length < 500; at += step) slots.push({ at, n: counts.get(at) ?? 0 });
  const dayOnly = bucketSeconds >= 86_400;
  const label = (ms: number) => {
    const d = new Date(ms).toISOString();
    return dayOnly ? d.slice(5, 10) : bucketSeconds >= 3600 ? `${d.slice(5, 10)} ${d.slice(11, 16)}` : d.slice(11, bucketSeconds < 60 ? 19 : 16);
  };
  const option = {
    ...baseOption(t),
    grid: { left: 36, right: 8, top: 8, bottom: 22 },
    tooltip: {
      ...baseOption(t).tooltip,
      trigger: "axis",
      axisPointer: { type: "shadow", shadowStyle: { color: t.grid, opacity: 0.35 } },
      formatter: (items: Array<{ dataIndex: number }>) => {
        const s = slots[items[0]?.dataIndex ?? 0];
        return s ? `${new Date(s.at).toISOString().replace("T", " ").slice(0, 19)} UTC<br/><b>${s.n.toLocaleString("en-IN")}</b> event${s.n === 1 ? "" : "s"}` : "";
      },
    },
    xAxis: {
      type: "category",
      data: slots.map((s) => label(s.at)),
      axisLine: { lineStyle: { color: t.baseline } },
      axisTick: { show: false },
      axisLabel: { color: t.inkMuted, fontSize: 10, hideOverlap: true },
    },
    yAxis: {
      type: "value",
      minInterval: 1,
      splitNumber: 3,
      axisLine: { show: false },
      axisTick: { show: false },
      splitLine: { lineStyle: { color: t.grid } },
      axisLabel: { color: t.inkMuted, fontSize: 10, formatter: (v: number) => compact(v) },
    },
    series: [{ type: "bar", name: "Events", itemStyle: { color: t.series[0], borderRadius: [2, 2, 0, 0] }, barCategoryGap: "20%", data: slots.map((s) => s.n) }],
  };
  return (
    <ReactECharts
      option={option}
      style={{ height: 120, width: "100%", cursor: "pointer" }}
      notMerge
      onEvents={{
        click: (e: { dataIndex: number }) => {
          const s = slots[e.dataIndex];
          if (s) onPick(new Date(s.at).toISOString(), new Date(s.at + step).toISOString());
        },
      }}
    />
  );
}
