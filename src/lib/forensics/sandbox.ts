import { chromium } from "playwright";

import { SCORING_RULES } from "./scoring";

// Ported from desas's sandbox/browser.py Sandbox — real Playwright-driven
// detonation (screenshot, redirect chain, password-field / generic-POST
// heuristics) rather than desas's deeper 3-pillar JS-behavioral
// exfiltration model, which would need injecting and classifying runtime
// script behavior — out of scope for this pass. Uses the Chromium binary
// this environment pre-installs rather than downloading one.

export interface SandboxResult {
  url: string;
  expandedUrl: string;
  redirectChain: string[];
  screenshotBase64: string | null;
  passwordFieldDetected: boolean;
  networkRequests: { method: string; url: string }[];
  score: number;
  reasons: string[];
  error: string | null;
}

export async function detonateUrl(url: string): Promise<SandboxResult> {
  const result: SandboxResult = {
    url,
    expandedUrl: url,
    redirectChain: [],
    screenshotBase64: null,
    passwordFieldDetected: false,
    networkRequests: [],
    score: 0,
    reasons: [],
    error: null,
  };

  let browser;
  try {
    browser = await chromium.launch({
      executablePath: process.env.PLAYWRIGHT_BROWSERS_PATH
        ? `${process.env.PLAYWRIGHT_BROWSERS_PATH}/chromium`
        : undefined,
      headless: true,
      timeout: 10_000,
    });
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();

    page.on("request", (req) => {
      if (result.networkRequests.length < 50) {
        result.networkRequests.push({ method: req.method(), url: req.url() });
      }
    });
    page.on("response", (res) => {
      if (res.url() !== url && !result.redirectChain.includes(res.url())) {
        result.redirectChain.push(res.url());
      }
    });

    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 10_000 });
    result.expandedUrl = page.url();

    result.passwordFieldDetected = (await page.locator('input[type="password"]').count()) > 0;

    const screenshot = await page.screenshot({ timeout: 5_000 });
    result.screenshotBase64 = screenshot.toString("base64");

    await browser.close();
  } catch (err) {
    result.error = err instanceof Error ? err.message : String(err);
    if (browser) await browser.close().catch(() => {});
  }

  result.score = calculateSandboxScore(result, result.reasons);
  return result;
}

function calculateSandboxScore(result: SandboxResult, reasons: string[]): number {
  let score = 0;
  const rules = SCORING_RULES.sandbox;

  if (result.passwordFieldDetected) {
    score += rules.passwordFieldDetected;
    reasons.push(`Sandbox (${result.url}): password input field detected (credential harvesting)`);
  }

  if (result.redirectChain.length > rules.redirectChain.minHopsToFlag) {
    score += rules.redirectChain.points;
    reasons.push(`Sandbox (${result.url}): long redirect chain (${result.redirectChain.length} hops)`);
  }

  const postRequests = result.networkRequests.filter((r) => r.method === "POST");
  if (postRequests.length > 0) {
    score += rules.genericPostFallback;
    reasons.push(`Sandbox (${result.url}): ${postRequests.length} POST request(s) detected (potential exfiltration)`);
  }

  return score;
}
