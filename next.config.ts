import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  experimental: {
    // forbidden() renders app/forbidden.tsx with a 403 for pages a role
    // can't open (lib/session pageGuard).
    authInterrupts: true,
    serverActions: {
      // Investigations accept log bundles and Forensics accepts .eml/.msg
      // files with attachments; the 1 MB default is too small for either.
      bodySizeLimit: "25mb",
    },
  },
};

export default nextConfig;
