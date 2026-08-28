import React from "react"
import { clsx } from "clsx"

function confidenceTier(n) {
  if (n >= 85) return { border: "border-low",      label: "High"   }
  if (n >= 60) return { border: "border-medium",   label: "Medium" }
  if (n >= 40) return { border: "border-high",     label: "Low"    }
  return              { border: "border-critical",  label: "Very Low" }
}

export default function ConfidencePill({ confidence, methodology }) {
  if (methodology == null) {
    console.error("[ConfidencePill] methodology is required but got null/undefined")
    return (
      <span className="font-data text-xs text-critical border-l-2 border-critical pl-2 py-0.5">
        ERR: no methodology
      </span>
    )
  }
  const n = Number(confidence)
  const tier = confidenceTier(n)
  return (
    <span
      title={methodology}
      className={clsx(
        "inline-flex items-center gap-1.5 border-l-2 pl-2 py-0.5",
        "text-xs font-data text-primary",
        tier.border
      )}
    >
      <span className="text-secondary">{tier.label}</span>
      <span className="font-bold">{n}%</span>
    </span>
  )
}
