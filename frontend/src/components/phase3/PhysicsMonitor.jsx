import React, { useState, useEffect, useCallback } from "react"
import { Activity, Zap, Cpu, RefreshCw, AlertCircle } from "lucide-react"

const API_BASE = import.meta.env.VITE_AXIOM_API_URL || "https://garuda-axiom-service.onrender.com"

export default function PhysicsMonitor() {
  const [agents, setAgents] = useState([])
  const [selectedAgent, setSelectedAgent] = useState(null)
  const [loading, setLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [errorMsg, setErrorMsg] = useState(null)

  const fetchLiveTelemetry = useCallback(async () => {
    setIsRefreshing(true)
    setErrorMsg(null)
    try {
      const resp = await fetch(`${API_BASE}/api/v1/axiom/stream`)
      if (resp.ok) {
        const data = await resp.json()
        const fleet = data.fleet || []
        setAgents(fleet)
        if (fleet.length > 0) {
          setSelectedAgent((prev) => fleet.find((a) => a.hostname === prev?.hostname) || fleet[0])
        } else {
          setSelectedAgent(null)
        }
      } else {
        setErrorMsg(`AXIOM service returned HTTP ${resp.status}`)
      }
    } catch (err) {
      console.warn("Error connecting to AXIOM:", err)
      setErrorMsg("Unable to connect to live AXIOM physics service.")
    } finally {
      setLoading(false)
      setIsRefreshing(false)
    }
  }, [])

  useEffect(() => {
    fetchLiveTelemetry()
    const interval = setInterval(fetchLiveTelemetry, 5000)
    return () => clearInterval(interval)
  }, [fetchLiveTelemetry])

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
          onClick={fetchLiveTelemetry}
          className="flex items-center gap-2 px-3 py-1.5 border text-xs font-mono transition-colors hover:bg-[#1E3349]"
          style={{ borderColor: "#1E3349", color: "#6B85A8" }}
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin text-[#FF6B00]" : ""}`} />
          <span>SYNC 1Hz</span>
        </button>
      </div>

      {errorMsg && (
        <div className="flex items-center gap-2 p-3 border bg-[#FF3B30]/10 border-[#FF3B30] text-[#FF3B30] font-mono text-xs">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Fleet Table */}
        <div className="lg:col-span-2 border" style={{ background: "#0D1521", borderColor: "#1E3349" }}>
          <div className="p-4 border-b flex justify-between items-center" style={{ borderColor: "#1E3349" }}>
            <span className="text-xs font-mono text-[#6B85A8] uppercase tracking-wider">
              Active Monitored Fleet ({agents.length} Endpoints)
            </span>
          </div>

          {agents.length === 0 ? (
            <div className="p-12 text-center text-[#6B85A8] font-mono text-xs">
              {loading ? "CONNECTING TO AXIOM SENSOR STREAM..." : "NO ENDPOINTS ACTIVELY STREAMING TELEMETRY. START GARUDA-AGENT ON TARGET HOSTS TO INGEST LIVE RAPL & PERF INVARIANTS."}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse font-mono text-xs">
                <thead>
                  <tr className="border-b text-[#6B85A8]" style={{ borderColor: "#1E3349" }}>
                    <th className="p-3">HOST</th>
                    <th className="p-3">IAS SCORE</th>
                    <th className="p-3">PKG POWER</th>
                    <th className="p-3">CACHE MISS</th>
                    <th className="p-3">ENTROPY</th>
                    <th className="p-3">STATUS</th>
                  </tr>
                </thead>
                <tbody>
                  {agents.map((agent) => {
                    const isSelected = selectedAgent?.hostname === agent.hostname
                    const score = Number(agent.ias_score || 0)
                    return (
                      <tr
                        key={agent.hostname}
                        onClick={() => setSelectedAgent(agent)}
                        className={`border-b cursor-pointer transition-colors hover:bg-[#1E3349]/50 ${
                          isSelected ? "bg-[#1E3349]/80 font-bold" : ""
                        }`}
                        style={{ borderColor: "#1E3349" }}
                      >
                        <td className="p-3 text-[#E8F0FE]">{agent.hostname}</td>
                        <td className="p-3 font-data font-bold" style={{ color: getIasColor(score) }}>
                          {score.toFixed(2)}
                        </td>
                        <td className="p-3 text-[#6B85A8]">
                          {(Number(agent.pkg_power_mw || 0) / 1000).toFixed(1)} W
                        </td>
                        <td className="p-3 text-[#6B85A8]">
                          {Number(agent.cache_miss_rate || 0).toFixed(1)}%
                        </td>
                        <td className="p-3 text-[#6B85A8]">{agent.entropy_avail ?? "N/A"}</td>
                        <td className="p-3">{getStatusBadge(agent.status)}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Selected Host Deep Telemetry Inspector */}
        <div className="border p-6 flex flex-col justify-between" style={{ background: "#0D1521", borderColor: "#1E3349" }}>
          {selectedAgent ? (
            <div className="flex flex-col gap-5 font-mono text-xs">
              <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: "#1E3349" }}>
                <span className="text-sm font-bold text-[#E8F0FE]">{selectedAgent.hostname}</span>
                {getStatusBadge(selectedAgent.status)}
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#6B85A8]">IAS Divergence:</span>
                <span className="font-bold text-sm" style={{ color: getIasColor(Number(selectedAgent.ias_score || 0)) }}>
                  {Number(selectedAgent.ias_score || 0).toFixed(2)} σ
                </span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#6B85A8]">RAPL Package Power:</span>
                <span className="text-[#E8F0FE]">
                  {(Number(selectedAgent.pkg_power_mw || 0) / 1000).toFixed(2)} W
                </span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#6B85A8]">RAPL Core Power:</span>
                <span className="text-[#E8F0FE]">
                  {(Number(selectedAgent.core_power_mw || 0) / 1000).toFixed(2)} W
                </span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#6B85A8]">L3 Cache Miss Spike:</span>
                <span className="text-[#E8F0FE]">
                  {Number(selectedAgent.cache_miss_rate || 0).toFixed(1)}%
                </span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#6B85A8]">Available Entropy:</span>
                <span className="text-[#E8F0FE]">{selectedAgent.entropy_avail ?? "N/A"} bits</span>
              </div>

              <div className="flex justify-between items-center border-t pt-3" style={{ borderColor: "#1E3349" }}>
                <span className="text-[#6B85A8]">Last Telemetry Sync:</span>
                <span className="text-[#34C759]">{selectedAgent.last_seen || "Just now"}</span>
              </div>

              {Number(selectedAgent.ias_score || 0) >= 3.0 && (
                <div className="p-3 border mt-2 bg-[#FF3B30]/10 border-[#FF3B30] text-[#FF3B30] text-[11px]">
                  ⚠ PHYSICAL ANOMALY: Severe execution power divergence. DHARMA Tier {Number(selectedAgent.ias_score) >= 5.0 ? "2" : "1"} intensification active.
                </div>
              )}
            </div>
          ) : (
            <div className="text-center text-[#6B85A8] font-mono text-xs my-auto">
              NO ENDPOINT SELECTED. TELEMETRY STREAMS DIRECTLY FROM MONITORED KERNEL DRIVERS.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
