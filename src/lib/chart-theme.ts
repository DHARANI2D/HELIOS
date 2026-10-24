"use client";

import { useResolvedTheme, type ResolvedTheme } from "@/lib/theme";

// Chart tokens from the dataviz reference palette, both modes selected (not
// flipped). Categorical slots 1-4 were validated adjacent-pairs against this
// app's own card surfaces (#ffffff light, #0f1520 dark): CVD ΔE ≥ 8.4,
// normal-vision ΔE ≥ 19.8. Light slots 3-4 sit under 3:1 contrast, so charts
// using them carry visible labels or a table (the relief rule).

export interface ChartTokens {
  surface: string;
  ink: string;
  inkSecondary: string;
  inkMuted: string;
  grid: string;
  baseline: string;
  series: string[];
  // De-emphasis gray for "everything else" in emphasis charts.
  muted: string;
  tooltipBg: string;
  tooltipBorder: string;
}

const LIGHT: ChartTokens = {
  surface: "#ffffff",
  ink: "#0b0b0b",
  inkSecondary: "#52514e",
  inkMuted: "#898781",
  grid: "#e1e0d9",
  baseline: "#c3c2b7",
  series: ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"],
  muted: "#c3c2b7",
  tooltipBg: "#ffffff",
  tooltipBorder: "rgba(11,11,11,0.10)",
};

const DARK: ChartTokens = {
  surface: "#0f1520",
  ink: "#f0efec",
  inkSecondary: "#c3c2b7",
  inkMuted: "#898781",
  grid: "#2c2c2a",
  baseline: "#383835",
  series: ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"],
  muted: "#4a4a46",
  tooltipBg: "#1a2130",
  tooltipBorder: "rgba(255,255,255,0.10)",
};

export function chartTokens(theme: ResolvedTheme): ChartTokens {
  return theme === "dark" ? DARK : LIGHT;
}

export function useChartTokens(): ChartTokens {
  return chartTokens(useResolvedTheme());
}

// Shared ECharts chrome: recessive hairline grid, muted axis text, a tooltip
// that matches the surface.
export function baseOption(t: ChartTokens) {
  return {
    textStyle: { fontFamily: "var(--font-geist-sans), system-ui, sans-serif", color: t.inkSecondary },
    tooltip: {
      backgroundColor: t.tooltipBg,
      borderColor: t.tooltipBorder,
      borderWidth: 1,
      textStyle: { color: t.ink, fontSize: 12 },
      extraCssText: "box-shadow: 0 4px 16px rgba(0,0,0,0.12); border-radius: 8px;",
    },
    animationDuration: 300,
  };
}

export function compact(n: number): string {
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
  if (Math.abs(n) >= 1000) return `${(n / 1000).toFixed(1).replace(/\.0$/, "")}K`;
  return String(Math.round(n));
}
