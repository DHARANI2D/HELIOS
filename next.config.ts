import type { NextConfig } from "next";

import { staticSecurityHeaders } from "./src/lib/security-headers";

const nextConfig: NextConfig = {
  // A self-contained server in .next/standalone with only the files it
  // needs: what the container image runs (Dockerfile).
  output: "standalone",
  poweredByHeader: false,
  // Set per build (the image's version) so a browser holding pages from the
  // previous version reloads instead of mixing the two during a rollout.
  deploymentId: process.env.HELIOS_DEPLOYMENT_ID || undefined,
  // Tesseract starts its OCR worker from a file in its own package and reads
  // its language data from beside it; bundling would break both paths.
  serverExternalPackages: ["tesseract.js", "@tesseract.js-data/eng"],
  // Those files are loaded by path at run time, so tracing can't see them;
  // the standalone server needs them copied in.
  outputFileTracingIncludes: {
    "/*": ["./node_modules/tesseract.js/src/worker-script/**/*", "./node_modules/tesseract.js-core/*.js", "./node_modules/tesseract.js-core/*.wasm", "./node_modules/@tesseract.js-data/eng/4.0.0_best_int/*"],
  },
  async headers() {
    return [{ source: "/:path*", headers: staticSecurityHeaders() }];
  },
  experimental: {
    // forbidden() renders app/forbidden.tsx with a 403 for pages a role
    // can't open (lib/session pageGuard).
    authInterrupts: true,
    serverActions: {
      // Investigations accept log bundles and Forensics accepts .eml/.msg
      // files with attachments; the 1 MB default is too small for either.
      bodySizeLimit: "25mb",
    },
    // proxy.ts runs on every request and buffers the body up to this size
    // (10 MB by default); larger uploads would arrive truncated.
    proxyClientMaxBodySize: "25mb",
  },
};

export default nextConfig;
