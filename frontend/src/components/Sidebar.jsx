import React from "react"
import { NavLink } from "react-router-dom"
import {
  ShieldAlert,
  Activity,
  Layers,
  History,
  Share2,
  FileCheck2,
  Wifi,
  Radio,
} from "lucide-react"
import { useGarudaStore } from "../store/useGarudaStore"
import TensionGauge from "./TensionGauge"

export default function Sidebar() {
  const { tensionIndex, conflictMode, realtimeConnected, stats } = useGarudaStore()

  const navLinks = [
    { to: "/", label: "SOC Dashboard", icon: Activity },
    { to: "/alerts", label: "Threat Alerts", icon: ShieldAlert, badge: stats?.critical_24h || null },
    { to: "/campaigns", label: "APT36 Campaigns", icon: Layers },
    { to: "/retrohunt", label: "Retrohunt Benchmark", icon: History },
    { to: "/stix", label: "STIX 2.1 Feed", icon: Share2 },
    { to: "/audit", label: "Analyst Audit Log", icon: FileCheck2 },
  ]

  return (
    <aside className="w-64 bg-navy-950 border-r border-navy-800 flex flex-col justify-between shrink-0 h-screen sticky top-0">
      {/* Brand Header */}
      <div>
        <div className="p-5 border-b border-navy-800/80 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-500 via-blue-600 to-indigo-700 flex items-center justify-center shadow-lg shadow-blue-500/20 border border-cyan-400/40">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-base font-black tracking-wider text-white">GARUDA</h1>
              <p className="text-[10px] text-gray-400 font-mono uppercase tracking-tight">Sovereign CTI Engine</p>
            </div>
          </div>

          <div className="flex items-center" title={realtimeConnected ? "Realtime WebSocket Online" : "Realtime Reconnecting"}>
            <span className={`w-2.5 h-2.5 rounded-full ${realtimeConnected ? "bg-emerald-400 animate-pulse" : "bg-amber-400"}`} />
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="p-3 space-y-1">
          {navLinks.map((link) => {
            const Icon = link.icon
            return (
              <NavLink
                key={link.to}
                to={link.to}
                className={({ isActive }) =>
                  `flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-semibold transition-all ${
                    isActive
                      ? "bg-blue-600 text-white shadow-lg shadow-blue-600/30"
                      : "text-gray-400 hover:text-gray-200 hover:bg-navy-800/70"
                  }`
                }
              >
                <div className="flex items-center space-x-2.5">
                  <Icon className="w-4 h-4" />
                  <span>{link.label}</span>
                </div>
                {link.badge && (
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500 text-white">
                    {link.badge}
                  </span>
                )}
              </NavLink>
            )
          })}
        </nav>
      </div>

      {/* Bottom Tension & Posture Widget */}
      <div className="p-3 border-t border-navy-800/80 space-y-3 bg-navy-950/60">
        <TensionGauge tension={tensionIndex} conflictMode={conflictMode} />

        <div className="px-2 py-1.5 rounded-lg bg-navy-900/60 border border-navy-800 text-[10px] text-gray-400 flex items-center justify-between font-mono">
          <div className="flex items-center space-x-1.5">
            <Radio className="w-3 h-3 text-cyan-400 animate-pulse" />
            <span>Monitored Patterns:</span>
          </div>
          <span className="text-gray-200 font-bold">{stats?.domains_monitored || 110}</span>
        </div>
      </div>
    </aside>
  )
}
