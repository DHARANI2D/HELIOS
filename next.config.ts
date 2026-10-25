import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Tesseract starts its OCR worker from a file in its own package and reads
  // its language data from beside it; bundling would break both paths.
  serverExternalPackages: ["tesseract.js", "@tesseract.js-data/eng"],
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
