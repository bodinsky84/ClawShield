import React from "react";
import { cn } from "@/lib/utils";

export function Badge({ className, variant = "default", ...props }) {
  const variants = {
    default: "bg-white/5 border-white/10 text-white/80",
    low: "bg-emerald-400/10 border-emerald-300/20 text-emerald-200",
    med: "bg-amber-400/10 border-amber-300/20 text-amber-200",
    high: "bg-rose-400/10 border-rose-300/20 text-rose-200"
  };

  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold",
        variants[variant],
        className
      )}
      {...props}
    />
  );
}
