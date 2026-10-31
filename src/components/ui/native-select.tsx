import * as React from "react";

import { cn } from "@/lib/utils";

// Plain <select> styled like Input — works inside server-rendered GET forms
// (filters) where the Radix Select's client-side state isn't needed.
function NativeSelect({ className, ...props }: React.ComponentProps<"select">) {
  return (
    <select
      data-slot="native-select"
      className={cn(
        // max-w-full: a select is as wide as its longest option; this lets it
        // shrink to its column instead of spilling out of it.
        "border-input dark:bg-input/30 h-9 max-w-full min-w-0 rounded-md border bg-transparent px-2.5 text-sm shadow-xs outline-none",
        "focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] disabled:opacity-50",
        className,
      )}
      {...props}
    />
  );
}

export { NativeSelect };
