import React from "react"

function relativeTime(timestamp) {
  if (!timestamp) return "—"
  const diff = Date.now() - new Date(timestamp).getTime()
  const secs = Math.floor(diff / 1000)
  if (secs < 60)   return `${secs}s ago`
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`
  return `${Math.floor(secs / 86400)}d ago`
}

export default function TimeAgo({ timestamp }) {
  const iso = timestamp ? new Date(timestamp).toISOString() : ""
  return (
    <span
      title={iso}
      className="font-data text-xs text-secondary cursor-default"
    >
      {relativeTime(timestamp)}
    </span>
  )
}
