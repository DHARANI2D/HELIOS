"use client";

import ReactECharts from "echarts-for-react";

import { baseOption, useChartTokens } from "@/lib/chart-theme";

interface Day {
  label: string;
  high: number;
  other: number;
}

// Emphasis form: the series that matters (critical & high) in the accent hue,
// everything else in the de-emphasis gray, stacked per day with a 2px surface
// gap between segments.
export function CaseVolumeChart({ days }: { days: Day[] }) {
  const t = useChartTokens();
  const segment = (color: string, top: boolean) => ({
    color,
    borderColor: t.surface,
    borderWidth: 1,
    borderRadius: top ? [4, 4, 0, 0] : 0,
  });
  const option = {
    ...baseOption(t),
    grid: { left: 32, right: 12, top: 36, bottom: 24 },
    legend: {
      top: 0,
      left: 0,
      icon: "roundRect",
      itemWidth: 10,
      itemHeight: 10,
      textStyle: { color: t.inkSecondary, fontSize: 12 },
      data: ["Critical & high", "Medium & below"],
    },
    tooltip: { ...baseOption(t).tooltip, trigger: "axis", axisPointer: { type: "shadow", shadowStyle: { color: t.grid, opacity: 0.35 } } },
    xAxis: {
      type: "category",
      data: days.map((d) => d.label),
      axisLine: { lineStyle: { color: t.baseline } },
      axisTick: { show: false },
      axisLabel: { color: t.inkMuted, fontSize: 11, interval: 1 },
    },
    yAxis: {
      type: "value",
      minInterval: 1,
      axisLine: { show: false },
      axisTick: { show: false },
      splitLine: { lineStyle: { color: t.grid } },
      axisLabel: { color: t.inkMuted, fontSize: 11 },
    },
    series: [
      {
        name: "Critical & high",
        type: "bar",
        stack: "cases",
        // Series-level color too, so the legend swatch matches the bars.
        itemStyle: { color: t.series[0] },
        barMaxWidth: 20,
        data: days.map((d) => ({ value: d.high, itemStyle: segment(t.series[0], d.other === 0) })),
      },
      {
        name: "Medium & below",
        type: "bar",
        stack: "cases",
        itemStyle: { color: t.muted },
        barMaxWidth: 20,
        data: days.map((d) => ({ value: d.other, itemStyle: segment(t.muted, true) })),
      },
    ],
  };
  return <ReactECharts option={option} style={{ height: 240, width: "100%" }} notMerge />;
}
