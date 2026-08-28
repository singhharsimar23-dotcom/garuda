import React from "react"

export default function SectionHeader({ title, subtitle, action }) {
  return (
    <div className="flex items-end justify-between pb-3 mb-4 border-b border-border">
      <div>
        <h2 className="text-base font-bold text-primary leading-tight">{title}</h2>
        {subtitle && (
          <p className="text-xs text-secondary mt-0.5">{subtitle}</p>
        )}
      </div>
      {action && (
        <div className="shrink-0">{action}</div>
      )}
    </div>
  )
}
