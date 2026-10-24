"use client";

import ReactECharts from "echarts-for-react";
import type { CaseSeverity } from "@prisma/client";

import { SEVERITY_CHART_COLOR, SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";
import { baseOption, useChartTokens } from "@/lib/chart-theme";

interface SeverityBarChartProps {
  counts: Record<CaseSeverity, number>;
}

// Status colors carry severity here; every bar is named on the axis and
// value-labeled at its tip, so color is never the only channel.
export function SeverityBarChart({ counts }: SeverityBarChartProps) {
  const t = useChartTokens();
  const categories = [...SEVERITY_ORDER].reverse();
  const values = categories.map((s) => counts[s] ?? 0);

  const option = {
    ...baseOption(t),
    grid: { left: 70, right: 36, top: 8, bottom: 24 },
    tooltip: {
      ...baseOption(t).tooltip,
      trigger: "item",
      formatter: (p: { name: string; value: number }) => `${p.name}: <strong>${p.value}</strong> case${p.value === 1 ? "" : "s"}`,
    },
    xAxis: {
      type: "value",
      minInterval: 1,
      axisLine: { show: false },
      axisTick: { show: false },
      splitLine: { lineStyle: { color: t.grid } },
      axisLabel: { color: t.inkMuted, fontSize: 11 },
    },
    yAxis: {
      type: "category",
      data: categories.map((s) => SEVERITY_LABEL[s]),
      axisLine: { lineStyle: { color: t.baseline } },
      axisTick: { show: false },
      axisLabel: { color: t.inkSecondary, fontSize: 12 },
    },
    series: [
      {
        type: "bar",
        data: values.map((v, i) => ({ value: v, itemStyle: { color: SEVERITY_CHART_COLOR[categories[i]].light, borderRadius: [0, 4, 4, 0] } })),
        barWidth: 14,
        label: { show: true, position: "right", color: t.inkSecondary, fontSize: 12 },
      },
    ],
  };

  return <ReactECharts option={option} style={{ height: 200, width: "100%" }} notMerge />;
}
