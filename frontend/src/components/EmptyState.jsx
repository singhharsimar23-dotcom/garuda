import React from "react"

/**
 * EmptyState — Production-grade honest empty state component
 * Used when a module has no real data yet.
 * Design: same dark theme, orange/gold accent, minimal, military-grade.
 */
export function EmptyState({
  icon = "📡",
  title = "NO REAL DATA COLLECTED YET",
  reason,
  message,
  lastAttempt = null,
  nextAttempt = null,
  dataSource = null,
  action = null,
}) {
  const displayReason = reason || message

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        minHeight: 280,
        padding: "40px 24px",
        color: "#6B85A8",
        textAlign: "center",
        gap: 12,
      }}
      className="w-full"
    >
      <div style={{ fontSize: 32, opacity: 0.6 }}>
        {typeof icon === "string" ? (
          icon
        ) : typeof icon === "function" ? (
          React.createElement(icon, { className: "w-8 h-8 text-ghost mb-1" })
        ) : (
          "📡"
        )}
      </div>

      <div
        style={{
          fontSize: 14,
          color: "#D0D7DE",
          fontWeight: 600,
          letterSpacing: "0.08em",
          textTransform: "uppercase",
          fontFamily: "JetBrains Mono, monospace",
        }}
      >
        {title}
      </div>

      {displayReason && (
        <div
          style={{
            fontSize: 12,
            color: "#8B949E",
            maxWidth: 480,
            lineHeight: 1.6,
          }}
        >
          {displayReason}
        </div>
      )}

      {dataSource && (
        <div
          style={{
            fontSize: 10,
            color: "#6B85A8",
            fontFamily: "JetBrains Mono, monospace",
            background: "#080E18",
            padding: "4px 10px",
            borderRadius: 3,
            border: "1px solid #1E3349",
          }}
        >
          SOURCE: {dataSource}
        </div>
      )}

      {(lastAttempt || nextAttempt) && (
        <div
          style={{
            fontSize: 10,
            color: "#484F58",
            marginTop: 6,
            fontFamily: "JetBrains Mono, monospace",
          }}
        >
          {lastAttempt && `Last collection attempt: ${lastAttempt}`}
          {lastAttempt && nextAttempt && " · "}
          {nextAttempt && `Next: ${nextAttempt}`}
        </div>
      )}

      {action && <div style={{ marginTop: 12 }}>{action}</div>}
    </div>
  )
}

export default EmptyState
