"use client";

// A script that runs while the server-rendered HTML is parsed (before first
// paint) and is inert on the client, so React doesn't warn about rendering
// a <script>. The pattern from Next's "preventing flash before hydration".
// The nonce lets it run under the Content Security Policy (src/proxy.ts).
export function InlineScript({ html, nonce }: { html: string; nonce?: string }) {
  return (
    <script
      nonce={nonce}
      type={typeof window === "undefined" ? "text/javascript" : "text/plain"}
      suppressHydrationWarning
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
