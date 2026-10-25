"use client";

// A script that runs while the server-rendered HTML is parsed (before first
// paint) and is inert on the client, so React doesn't warn about rendering
// a <script>. The pattern from Next's "preventing flash before hydration".
export function InlineScript({ html }: { html: string }) {
  return (
    <script
      type={typeof window === "undefined" ? "text/javascript" : "text/plain"}
      suppressHydrationWarning
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
