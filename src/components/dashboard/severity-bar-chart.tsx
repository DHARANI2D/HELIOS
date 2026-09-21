"use client";

import ReactECharts from "echarts-for-react";

import {
  SEVERITY_CHART_COLOR,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
} from "@/lib/severity";
import type { CaseSeverity } from "@prisma/client";

interface SeverityBarChartProps {
  counts: Record<CaseSeverity, number>;
}

// Chart chrome tokens straight from the dataviz skill's reference palette
// (light mode only for now — the app doesn't have a dark-mode toggle yet).
const INK_SECONDARY = "#52514e";
const INK_MUTED = "#898781";
const GRIDLINE = "#e1e0d9";

export function SeverityBarChart({ counts }: SeverityBarChartProps) {
  const categories = [...SEVERITY_ORDER].reverse();
  const values = categories.map((s) => counts[s] ?? 0);
  const colors = categories.map((s) => SEVERITY_CHART_COLOR[s].light);

  const option = {
    grid: { left: 90, right: 24, top: 12, bottom: 24 },
    tooltip: {
      trigger: "item",
      formatter: (p: { name: string; value: number }) =>
        `${p.name}: <strong>${p.value}</strong> case${p.value === 1 ? "" : "s"}`,
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
      data: categories.map((s) => SEVERITY_LABEL[s]),
      axisLine: { lineStyle: { color: GRIDLINE } },
      axisTick: { show: false },
      axisLabel: { color: INK_SECONDARY, fontSize: 12 },
    },
    series: [
      {
        type: "bar",
        data: values.map((v, i) => ({
          value: v,
          itemStyle: { color: colors[i], borderRadius: [0, 4, 4, 0] },
        })),
        barWidth: 16,
        label: {
          show: true,
          position: "right",
          color: INK_SECONDARY,
          fontSize: 12,
        },
      },
    ],
  };

  return (
    <ReactECharts
      option={option}
      style={{ height: 220, width: "100%" }}
      notMerge
    />
  );
}
