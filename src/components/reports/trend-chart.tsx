"use client";

import ReactECharts from "echarts-for-react";

import { baseOption, useChartTokens } from "@/lib/chart-theme";

interface Point {
  label: string;
  opened: number;
  closed: number;
}

// Two series over time: categorical slots 1-2, 2px lines, legend plus a
// direct label at each line's end, axis crosshair tooltip. The table below
// carries the same numbers for screen readers and print.
export function TrendChart({ points }: { points: Point[] }) {
  const t = useChartTokens();
  const line = (name: string, color: string, values: number[]) => ({
    name,
    type: "line",
    data: values,
    showSymbol: points.length <= 31,
    symbolSize: 8,
    itemStyle: { color, borderColor: t.surface, borderWidth: 2 },
    lineStyle: { width: 2, color },
    emphasis: { focus: "series" },
    endLabel: { show: true, formatter: name, color: t.inkSecondary, fontSize: 11, distance: 6 },
  });
  const option = {
    ...baseOption(t),
    grid: { left: 36, right: 64, top: 36, bottom: 28 },
    legend: { top: 0, left: 0, icon: "roundRect", itemWidth: 10, itemHeight: 10, textStyle: { color: t.inkSecondary, fontSize: 12 }, data: ["Opened", "Closed"] },
    tooltip: { ...baseOption(t).tooltip, trigger: "axis", axisPointer: { type: "line", lineStyle: { color: t.baseline } } },
    xAxis: {
      type: "category",
      boundaryGap: false,
      data: points.map((p) => p.label),
      axisLine: { lineStyle: { color: t.baseline } },
      axisTick: { show: false },
      axisLabel: { color: t.inkMuted, fontSize: 11, hideOverlap: true },
    },
    yAxis: { type: "value", minInterval: 1, axisLine: { show: false }, axisTick: { show: false }, splitLine: { lineStyle: { color: t.grid } }, axisLabel: { color: t.inkMuted, fontSize: 11 } },
    series: [line("Opened", t.series[0], points.map((p) => p.opened)), line("Closed", t.series[1], points.map((p) => p.closed))],
  };
  return (
    <div>
      <ReactECharts option={option} style={{ height: 260, width: "100%" }} notMerge />
      <details className="mt-2 text-xs">
        <summary className="cursor-pointer text-muted-foreground">Show as table</summary>
        <div className="mt-2 max-h-64 overflow-y-auto">
          <table className="w-full text-left tabular">
            <thead className="text-muted-foreground">
              <tr><th className="py-1 font-medium">Period</th><th className="py-1 text-right font-medium">Opened</th><th className="py-1 text-right font-medium">Closed</th></tr>
            </thead>
            <tbody>
              {points.map((p) => (
                <tr key={p.label} className="border-t"><td className="py-1">{p.label}</td><td className="py-1 text-right">{p.opened}</td><td className="py-1 text-right">{p.closed}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
