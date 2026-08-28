import React, { useState } from "react"
import { NavLink, useLocation } from "react-router-dom"
import {
  Shield,
  Radar,
  Server,
  Network,
  Fingerprint,
  Activity,
} from "lucide-react"
import { useGarudaStore } from "../store/useGarudaStore"
import TensionGauge from "./TensionGauge"

// ---------------------------------------------------------------------------
// Rail items
// ---------------------------------------------------------------------------
const RAIL = [
  {
    to: "/operations",
    icon: Shield,
    label: "Operations",
    matchPaths: ["/", "/operations", "/alerts", "/campaigns", "/retrohunt", "/audit"],
    context: "operations",
  },
  {
    to: "/intelligence",
    icon: Radar,
    label: "Intelligence",
    matchPaths: ["/intelligence", "/stix"],
    context: "intelligence",
  },
  {
    to: "/surface",
    icon: Server,
    label: "Attack Surface",
    matchPaths: ["/surface"],
    context: "surface",
  },
  {
    to: "/network",
    icon: Network,
    label: "Network Controls",
    matchPaths: ["/network"],
    context: "network",
  },
  {
    to: "/attribution",
    icon: Fingerprint,
    label: "Attribution",
    matchPaths: ["/attribution"],
    context: "attribution",
  },
  {
    to: "/system",
    icon: Activity,
    label: "System",
    matchPaths: ["/system"],
    context: "system",
  },
]

// ---------------------------------------------------------------------------
// Stat row inside context panel
// ---------------------------------------------------------------------------
function StatRow({ label, value, highlight }) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-border last:border-0">
      <span className="text-2xs text-secondary uppercase tracking-wider">{label}</span>
      <span className={`font-data text-xs font-bold ${highlight ? "text-saffron" : "text-primary"}`}>
        {value ?? "—"}
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Per-section context panels
// ---------------------------------------------------------------------------
function OperationsPanel({ stats, tensionIndex, conflictMode }) {
  return (
    <div className="p-3 space-y-0">
      <StatRow label="Alerts 24h"       value={stats?.total_alerts_24h} />
      <StatRow label="Critical"         value={stats?.critical_24h}     highlight={stats?.critical_24h > 0} />
      <StatRow label="Active Campaigns" value={stats?.active_campaigns} />
      <div className="pt-2">
        <TensionGauge tension={tensionIndex} conflictMode={conflictMode} />
      </div>
    </div>
  )
}

function IntelligencePanel({ systemHealth }) {
  const svc = systemHealth?.services
  return (
    <div className="p-3 space-y-0">
      <StatRow label="STIX Objects"    value={svc?.stix?.object_count} />
      <StatRow label="Subscribers"     value={svc?.taxii?.subscriber_count} />
      <StatRow label="Collections"     value={svc?.taxii?.collection_count} />
      <StatRow label="Last Pull"       value={svc?.taxii?.last_pull ? new Date(svc.taxii.last_pull).toLocaleTimeString() : "—"} />
    </div>
  )
}

function SurfacePanel({ systemHealth }) {
  const svc = systemHealth?.services?.easm
  return (
    <div className="p-3 space-y-0">
      <StatRow label="Orgs Monitored"   value={svc?.org_count} />
      <StatRow label="Open Findings"    value={svc?.open_findings} />
      <StatRow label="KEV Matches"      value={svc?.kev_matches}    highlight={svc?.kev_matches > 0} />
      <StatRow label="Critical Exposure" value={svc?.critical_exposure} highlight={svc?.critical_exposure > 0} />
    </div>
  )
}

function NetworkPanel({ systemHealth }) {
  const svc = systemHealth?.services?.rpz
  return (
    <div className="p-3 space-y-0">
      <StatRow label="RPZ Entries"   value={svc?.entry_count} />
      <StatRow label="Blocked Today" value={svc?.blocked_today} />
      <StatRow label="pDNS Matches"  value={svc?.pdns_matches} />
      <StatRow label="Zone Serial"   value={svc?.zone_serial} />
    </div>
  )
}

function AttributionPanel({ systemHealth }) {
  const svc = systemHealth?.services?.attribution
  return (
    <div className="p-3 space-y-0">
      <StatRow label="Campaigns"    value={svc?.campaign_count} />
      <StatRow label="Clusters"     value={svc?.cluster_count} />
      <StatRow label="Avg Match"    value={svc?.avg_match ? `${(svc.avg_match * 100).toFixed(0)}%` : "—"} />
      <StatRow label="Data Since"   value={svc?.data_since || "—"} />
    </div>
  )
}

function SystemPanel({ systemHealth }) {
  const svcs = systemHealth?.services || {}
  const total   = Object.keys(svcs).length
  const healthy = Object.values(svcs).filter((s) => s?.status === "ok").length
  return (
    <div className="p-3 space-y-0">
      <StatRow label="APIs Healthy"      value={`${healthy}/${total}`} highlight={healthy < total} />
      <StatRow label="Rate Limit Warns"  value={systemHealth?.rate_limit_warnings ?? 0} />
      <StatRow label="GH Actions"        value={systemHealth?.gh_last_run || "—"} />
      <StatRow label="Supabase"          value={svcs?.supabase?.status === "ok" ? "Connected" : "—"} />
    </div>
  )
}

const PANELS = {
  operations:   OperationsPanel,
  intelligence: IntelligencePanel,
  surface:      SurfacePanel,
  network:      NetworkPanel,
  attribution:  AttributionPanel,
  system:       SystemPanel,
}

// ---------------------------------------------------------------------------
// Main Sidebar
// ---------------------------------------------------------------------------
export default function Sidebar() {
  const location = useLocation()
  const { tensionIndex, conflictMode, stats, systemHealth } = useGarudaStore()
  const [openPanel, setOpenPanel] = useState(() => {
    // Default to whichever section the current path belongs to
    const match = RAIL.find((r) =>
      r.matchPaths.some((p) => location.pathname === p || location.pathname.startsWith(p + "/"))
    )
    return match?.context || "operations"
  })

  function handleRailClick(context) {
    setOpenPanel((prev) => (prev === context ? null : context))
  }

  const ActivePanel = openPanel ? PANELS[openPanel] : null

  return (
    <aside className="flex h-screen sticky top-8 shrink-0">
      {/* === Left Rail (48px) === */}
      <div
        className="flex flex-col items-center py-2 gap-1 border-r border-border"
        style={{ width: 48, background: "#060B14" }}
      >
        {RAIL.map(({ to, icon: Icon, label, context, matchPaths }) => {
          const isActive =
            openPanel === context ||
            matchPaths.some(
              (p) => location.pathname === p || location.pathname.startsWith(p + "/")
            )
          return (
            <NavLink
              key={to}
              to={to}
              title={label}
              onClick={() => handleRailClick(context)}
              className={`
                flex items-center justify-center w-full h-10
                border-l-2 transition-colors duration-[80ms]
                ${isActive
                  ? "border-saffron bg-surface text-saffron"
                  : "border-transparent text-ghost hover:text-secondary hover:bg-surface"
                }
              `}
            >
              <Icon className="w-4 h-4" strokeWidth={isActive ? 2 : 1.5} />
            </NavLink>
          )
        })}
      </div>

      {/* === Context Panel (220px) === */}
      {ActivePanel && (
        <div
          className="flex flex-col border-r border-border overflow-y-auto"
          style={{ width: 220, background: "#0D1521" }}
        >
          {/* Panel header */}
          <div className="px-3 py-2.5 border-b border-border">
            <span className="text-2xs font-bold text-secondary uppercase tracking-widest">
              {RAIL.find((r) => r.context === openPanel)?.label}
            </span>
          </div>

          <ActivePanel
            stats={stats}
            tensionIndex={tensionIndex}
            conflictMode={conflictMode}
            systemHealth={systemHealth}
          />
        </div>
      )}
    </aside>
  )
}
