import * as React from "react";

import { cn } from "@/lib/utils";

// Plain <select> styled like Input — works inside server-rendered GET forms
// (filters) where the Radix Select's client-side state isn't needed.
function NativeSelect({ className, ...props }: React.ComponentProps<"select">) {
  return (
    <select
      data-slot="native-select"
      className={cn(
        "border-input dark:bg-input/30 h-9 rounded-md border bg-transparent px-2.5 text-sm shadow-xs outline-none",
        "focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] disabled:opacity-50",
        className,
      )}
      {...props}
    />
  );
}

export { NativeSelect };
