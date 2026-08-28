import React from "react"

export default function EmptyState({ icon: Icon, title, message, action, collectionNote }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center gap-3">
      {Icon && <Icon className="w-8 h-8 text-ghost mb-1" strokeWidth={1.5} />}
      <p className="text-sm font-semibold text-secondary">{title || "No data"}</p>
      {message && (
        <p className="text-xs text-ghost max-w-sm leading-relaxed">{message}</p>
      )}
      {collectionNote && (
        <p className="text-xs text-ghost max-w-sm leading-relaxed border border-border px-3 py-2 mt-1">
          {collectionNote}
        </p>
      )}
      {action && <div className="mt-3">{action}</div>}
    </div>
  )
}
