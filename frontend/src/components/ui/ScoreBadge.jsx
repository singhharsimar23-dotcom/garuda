import React from "react"
import { clsx } from "clsx"

export default function ScoreBadge({ score }) {
  const n = Number(score)
  const cls = clsx(
    "inline-block w-12 text-center font-data font-bold text-sm leading-6 shrink-0",
    n >= 85 ? "bg-critical text-white"
    : n >= 70 ? "bg-high text-void"
    : n >= 40 ? "bg-medium text-void"
    : "bg-ghost text-primary"
  )
  return <span className={cls}>{n}</span>
}
