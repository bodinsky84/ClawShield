import React from "react";
import { cn } from "@/lib/utils";

export function Button({ className, variant = "default", ...props }) {
  const base =
    "inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold transition active:translate-y-[1px] disabled:opacity-50 disabled:pointer-events-none";

  const variants = {
    default:
      "bg-gradient-to-br from-blue-400/25 to-pink-400/20 border border-white/10 hover:border-white/20 hover:bg-white/10",
    secondary:
      "bg-white/5 border border-white/10 hover:bg-white/10 hover:border-white/20",
    ghost:
      "bg-transparent border border-white/10 hover:bg-white/5 hover:border-white/20"
  };

  return <button className={cn(base, variants[variant], className)} {...props} />;
}
