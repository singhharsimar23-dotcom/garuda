import React, { useState, useEffect } from "react"
import { Activity, Zap, Cpu, RefreshCw } from "lucide-react"

// Mock active agent telemetry data for initial display / fallback
const INITIAL_AGENTS = [
  {
    id: "delhi-core-gw",
    hostname: "delhi-core-gw.nic.in",
    ias_score: 5.42,
    pkg_power_mw: 42800,
    core_power_mw: 31200,
    cache_miss_rate: 8.4,
    entropy_avail: 120,
    status: "CRITICAL",
    last_seen: "2s ago",
  },
  {
    id: "mumbai-dc-01",
    hostname: "mumbai-dc-01.mil.in",
    ias_score: 2.15,
    pkg_power_mw: 24500,
    core_power_mw: 18100,
    cache_miss_rate: 3.1,
    entropy_avail: 3840,
    status: "SUSPICIOUS",
    last_seen: "4s ago",
  },
  {
    id: "drdo-sensor-hub",
    hostname: "drdo-sensor-hub.gov.in",
    ias_score: 0.42,
    pkg_power_mw: 14200,
    core_power_mw: 9800,
    cache_miss_rate: 1.2,
    entropy_avail: 4096,
    status: "TRUSTED",
    last_seen: "1s ago",
  },
  {
    id: "chandigarh-edge-03",
    hostname: "chd-edge-03.nic.in",
    ias_score: 0.12,
    pkg_power_mw: 12800,
    core_power_mw: 8900,
    cache_miss_rate: 0.9,
    entropy_avail: 4096,
    status: "BASELINING",
    last_seen: "Just now",
  },
]

export default function PhysicsMonitor() {
  const [agents, setAgents] = useState(INITIAL_AGENTS)
  const [selectedAgent, setSelectedAgent] = useState(INITIAL_AGENTS[0])
  const [isRefreshing, setIsRefreshing] = useState(false)

  const getStatusBadge = (status) => {
    switch (status) {
      case "CRITICAL":
        return <span className="px-2 py-0.5 text-xs font-mono font-bold bg-[#FF3B30]/20 text-[#FF3B30] border border-[#FF3B30]">CRITICAL</span>
      case "COMPROMISED":
        return <span className="px-2 py-0.5 text-xs font-mono font-bold bg-[#FF6B00]/20 text-[#FF6B00] border border-[#FF6B00]">COMPROMISED</span>
      case "SUSPICIOUS":
        return <span className="px-2 py-0.5 text-xs font-mono font-semibold bg-[#FFD60A]/20 text-[#FFD60A] border border-[#FFD60A]">SUSPICIOUS</span>
      case "TRUSTED":
        return <span className="px-2 py-0.5 text-xs font-mono bg-[#34C759]/20 text-[#34C759] border border-[#34C759]">TRUSTED</span>
      default:
        return <span className="px-2 py-0.5 text-xs font-mono bg-[#6B85A8]/20 text-[#6B85A8] border border-[#6B85A8]">BASELINING</span>
    }
  }

  const getIasColor = (score) => {
    if (score >= 5.0) return "#FF3B30"
    if (score >= 3.0) return "#FF9500"
    if (score >= 1.5) return "#FFD60A"
    return "#34C759"
  }

  return (
    <div className="flex flex-col gap-6 p-6" style={{ background: "#060B14", color: "#E8F0FE" }}>
      {/* Header Bar */}
      <div className="flex items-center justify-between border-b pb-4" style={{ borderColor: "#1E3349" }}>
        <div>
          <div className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-[#FF6B00]" />
            <h1 className="text-xl font-bold tracking-wider font-mono">AXIOM-II // MICROARCHITECTURAL PHYSICS RADAR</h1>
          </div>
          <p className="text-xs text-[#6B85A8] mt-1 font-mono">
            Continuous 1Hz RAPL energy counters, hardware cache metrics, and kernel scheduler invariants
          </p>
        </div>
        <button
          onClick={() => {
            setIsRefreshing(true)
            setTimeout(() => setIsRefreshing(false), 500)
          }}
          className="flex items-center gap-2 px-3 py-1.5 text-xs font-mono border transition-colors hover:bg-[#0D1521]"
          style={{ borderColor: "#1E3349", color: "#6B85A8" }}
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
          SYNC 1Hz
        </button>
      </div>

      {/* Grid: Host Telemetry Table & Detail Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Host Table */}
        <div className="lg:col-span-2 border p-4" style={{ background: "#0D1521", borderColor: "#1E3349" }}>
          <div className="text-xs font-mono text-[#6B85A8] uppercase tracking-wider mb-3">
            Active Monitored Fleet ({agents.length} Endpoints)
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b text-[#6B85A8]" style={{ borderColor: "#1E3349" }}>
                  <th className="py-2 px-2">HOST</th>
                  <th className="py-2 px-2">IAS SCORE</th>
                  <th className="py-2 px-2">PKG POWER</th>
                  <th className="py-2 px-2">CACHE MISS</th>
                  <th className="py-2 px-2">ENTROPY</th>
                  <th className="py-2 px-2">STATUS</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((agent) => (
                  <tr
                    key={agent.id}
                    onClick={() => setSelectedAgent(agent)}
                    className={`border-b cursor-pointer transition-colors ${
                      selectedAgent.id === agent.id ? "bg-[#1E3349]/40" : "hover:bg-[#1E3349]/20"
                    }`}
                    style={{ borderColor: "#1E3349" }}
                  >
                    <td className="py-2.5 px-2 text-[#E8F0FE] font-bold">{agent.hostname}</td>
                    <td className="py-2.5 px-2 font-bold" style={{ color: getIasColor(agent.ias_score) }}>
                      {agent.ias_score.toFixed(2)}
                    </td>
                    <td className="py-2.5 px-2 text-[#6B85A8]">{(agent.pkg_power_mw / 1000).toFixed(1)} W</td>
                    <td className="py-2.5 px-2 text-[#6B85A8]">{agent.cache_miss_rate}%</td>
                    <td className="py-2.5 px-2 text-[#6B85A8]">{agent.entropy_avail}</td>
                    <td className="py-2.5 px-2">{getStatusBadge(agent.status)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Host Deep Dive */}
        <div className="border p-4 flex flex-col justify-between" style={{ background: "#0D1521", borderColor: "#1E3349" }}>
          <div>
            <div className="flex items-center justify-between border-b pb-2 mb-4" style={{ borderColor: "#1E3349" }}>
              <div className="text-xs font-mono font-bold text-[#E8F0FE]">{selectedAgent.hostname}</div>
              {getStatusBadge(selectedAgent.status)}
            </div>

            <div className="flex flex-col gap-3 font-mono text-xs">
              <div className="flex justify-between border-b py-1" style={{ borderColor: "#1E3349" }}>
                <span className="text-[#6B85A8]">IAS Divergence:</span>
                <span className="font-bold" style={{ color: getIasColor(selectedAgent.ias_score) }}>
                  {selectedAgent.ias_score.toFixed(2)} σ
                </span>
              </div>
              <div className="flex justify-between border-b py-1" style={{ borderColor: "#1E3349" }}>
                <span className="text-[#6B85A8]">RAPL Package Power:</span>
                <span className="text-[#E8F0FE]">{(selectedAgent.pkg_power_mw / 1000).toFixed(2)} W</span>
              </div>
              <div className="flex justify-between border-b py-1" style={{ borderColor: "#1E3349" }}>
                <span className="text-[#6B85A8]">RAPL Core Power:</span>
                <span className="text-[#E8F0FE]">{(selectedAgent.core_power_mw / 1000).toFixed(2)} W</span>
              </div>
              <div className="flex justify-between border-b py-1" style={{ borderColor: "#1E3349" }}>
                <span className="text-[#6B85A8]">L3 Cache Miss Spike:</span>
                <span className="text-[#E8F0FE]">{selectedAgent.cache_miss_rate}%</span>
              </div>
              <div className="flex justify-between border-b py-1" style={{ borderColor: "#1E3349" }}>
                <span className="text-[#6B85A8]">Available Entropy:</span>
                <span className="text-[#E8F0FE]">{selectedAgent.entropy_avail} bits</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-[#6B85A8]">Last Telemetry Sync:</span>
                <span className="text-[#6B85A8]">{selectedAgent.last_seen}</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t text-xs font-mono text-[#6B85A8]" style={{ borderColor: "#1E3349" }}>
            {selectedAgent.ias_score >= 5.0 ? (
              <p className="text-[#FF3B30]">
                ⚠️ PHYSICAL ANOMALY: Severe execution power divergence. DHARMA Tier 0 intensification active.
              </p>
            ) : (
              <p className="text-[#34C759]">
                ✓ INVARIANTS SATISFIED: Host execution parameters conform to uncontaminated baseline.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
