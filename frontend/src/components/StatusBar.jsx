import React, { useEffect } from "react"
import { useGarudaStore } from "../store/useGarudaStore"
import StatusDot from "./ui/StatusDot"

const SERVICES = [
  { key: "operations", label: "Operations" },
  { key: "taxii",      label: "TAXII Feed"  },
  { key: "easm",       label: "EASM Scan"   },
  { key: "rpz",        label: "RPZ Zone"    },
  { key: "gh_actions", label: "GH Actions"  },
]

function tensionColor(t) {
  if (t >= 0.8) return "text-critical"
  if (t >= 0.6) return "text-high"
  if (t >= 0.4) return "text-medium"
  return "text-low"
}

export default function StatusBar() {
  const {
    tensionIndex,
    conflictMode,
    realtimeConnected,
    systemHealth,
    setSystemHealth,
  } = useGarudaStore()

  useEffect(() => {
    async function fetchHealth() {
      try {
        const res = await fetch("/api/health")
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = await res.json()
        setSystemHealth(data)
      } catch (err) {
        // Don't overwrite existing health on transient error
        console.warn("[StatusBar] Health poll failed:", err.message)
      }
    }
    fetchHealth()
    const interval = setInterval(fetchHealth, 60_000)
    return () => clearInterval(interval)
  }, [setSystemHealth])

  function serviceStatus(key) {
    if (!systemHealth || !systemHealth.services) return "unknown"
    const svc = systemHealth.services[key]
    if (!svc) return "unknown"
    if (svc.status === "ok")    return "live"
    if (svc.status === "stale") return "stale"
    if (svc.status === "error") return "error"
    return "unknown"
  }

  function serviceError(key) {
    if (!systemHealth?.services) return null
    return systemHealth.services[key]?.error || null
  }

  const tension = typeof tensionIndex === "number" ? tensionIndex : 0.5
  const tensionDisplay = tension.toFixed(2)

  return (
    <header
      className="fixed top-0 left-0 right-0 z-50 h-8 flex items-center justify-between px-3 border-b border-border"
      style={{ background: "#060B14" }}
    >
      {/* Left — brand */}
      <span className="text-saffron font-bold text-sm leading-none tracking-tight shrink-0">
        GARUDA गरुड
      </span>

      {/* Center — service status */}
      <div className="flex items-center gap-4 text-2xs text-secondary">
        {SERVICES.map(({ key, label }) => (
          <span
            key={key}
            className="flex items-center gap-1.5"
            title={serviceError(key) || label}
          >
            <StatusDot status={serviceStatus(key)} />
            <span>{label}</span>
          </span>
        ))}
        {realtimeConnected && (
          <span className="flex items-center gap-1.5">
            <StatusDot status="live" />
            <span>Realtime</span>
          </span>
        )}
      </div>

      {/* Right — tension + conflict + analyst */}
      {/* Right — search + tension + conflict + analyst */}
      <div className="flex items-center gap-3 text-2xs shrink-0">
        <button
          onClick={() => window.dispatchEvent(new KeyboardEvent("keydown", { key: "k", metaKey: true }))}
          className="flex items-center gap-1.5 bg-raised hover:bg-surface text-secondary hover:text-primary px-2 py-0.5 border border-border transition-colors font-data"
        >
          <span>Search</span>
          <kbd className="bg-void px-1 text-[9px] text-ghost">⌘K</kbd>
        </button>

        <span className="text-secondary">
          Tension:{" "}
          <span className={`font-data font-bold ${tensionColor(tension)}`}>
            {tensionDisplay}
          </span>
        </span>

        {conflictMode && (
          <span className="bg-saffron text-void font-bold px-2 py-0.5 text-2xs tracking-widest">
            CONFLICT MODE ON
          </span>
        )}

        <span className="text-ghost font-data">
          {systemHealth?.analyst_id || "ANALYST"}
        </span>
      </div>
    </header>
  )
}

