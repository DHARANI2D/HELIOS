"use client";

import ReactECharts from "echarts-for-react";

import type { TacticCoverage } from "@/lib/mitre/coverage";

// Single-hue bars: tactic identity is already carried by the axis labels,
// so per-bar color would just be decoration, not encoding — this is a
// magnitude ranking, not a categorical-identity comparison.
const BAR_COLOR = "#2a78d6"; // categorical slot 1, dataviz skill palette
const INK_SECONDARY = "#52514e";
const INK_MUTED = "#898781";
const GRIDLINE = "#e1e0d9";

export function CoverageChart({ tactics }: { tactics: TacticCoverage[] }) {
  const sorted = [...tactics].filter((t) => t.caseCount > 0).sort((a, b) => a.caseCount - b.caseCount);

  if (sorted.length === 0) {
    return (
      <p className="py-10 text-center text-sm text-muted-foreground">
        No MITRE technique references recorded yet.
      </p>
    );
  }

  const option = {
    grid: { left: 160, right: 32, top: 12, bottom: 24 },
    tooltip: {
      trigger: "item",
      formatter: (p: { name: string; value: number }) => `${p.name}: <strong>${p.value}</strong> case(s)`,
    },
    xAxis: {
      type: "value",
      minInterval: 1,
      axisLine: { show: false },
      axisTick: { show: false },
      splitLine: { lineStyle: { color: GRIDLINE } },
      axisLabel: { color: INK_MUTED, fontSize: 11 },
    },
    yAxis: {
      type: "category",
      data: sorted.map((t) => t.name),
      axisLine: { lineStyle: { color: GRIDLINE } },
      axisTick: { show: false },
      axisLabel: { color: INK_SECONDARY, fontSize: 11 },
    },
    series: [
      {
        type: "bar",
        data: sorted.map((t) => t.caseCount),
        barWidth: 14,
        itemStyle: { color: BAR_COLOR, borderRadius: [0, 4, 4, 0] },
        label: { show: true, position: "right", color: INK_SECONDARY, fontSize: 11 },
      },
    ],
  };

  return (
    <ReactECharts
      option={option}
      style={{ height: Math.max(220, sorted.length * 32), width: "100%" }}
      notMerge
    />
  );
}
