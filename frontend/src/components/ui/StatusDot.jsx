import React from "react"
import { clsx } from "clsx"

const STATUS_MAP = {
  live:    { color: "bg-low",      pulse: true,  label: "Live"    },
  stale:   { color: "bg-gold",     pulse: false, label: "Stale"   },
  error:   { color: "bg-critical", pulse: false, label: "Error"   },
  unknown: { color: "bg-ghost",    pulse: false, label: "Unknown" },
}

export default function StatusDot({ status = "unknown", title, className }) {
  const cfg = STATUS_MAP[status] || STATUS_MAP.unknown
  return (
    <span
      title={title || cfg.label}
      className={clsx(
        "inline-block w-2 h-2 rounded-full shrink-0",
        cfg.color,
        cfg.pulse && "animate-pulse",
        className
      )}
    />
  )
}
