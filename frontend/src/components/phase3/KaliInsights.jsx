import React, { useState, useEffect, useCallback } from "react"
import { Shield, Sparkles, CheckCircle2, AlertTriangle, RefreshCw, Activity, Cpu } from "lucide-react"

const API_BASE = import.meta.env.VITE_BRAHMA_API_URL || "https://garuda-brahma-service.onrender.com"

export default function KaliInsights() {
  const [discoveries, setDiscoveries] = useState([])
  const [loading, setLoading] = useState(true)
  const [synthesizing, setSynthesizing] = useState(false)
  const [errorMsg, setErrorMsg] = useState(null)

  const fetchDiscoveries = useCallback(async () => {
    try {
      const resp = await fetch(`${API_BASE}/api/v1/kali/discoveries?limit=10`)
      if (resp.ok) {
        const data = await resp.json()
        setDiscoveries(data.discoveries || [])
      }
    } catch (err) {
      console.warn("Failed fetching KALI discoveries", err)
      setErrorMsg("Unable to connect to KALI ANPS service.")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchDiscoveries()
  }, [fetchDiscoveries])

  const handleRunMCTS = async () => {
    setSynthesizing(true)
    setErrorMsg(null)
    try {
      const resp = await fetch(`${API_BASE}/api/v1/kali/synthesize`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ num_simulations: 500, top_k: 10 }),
      })
      if (!resp.ok) {
        throw new Error("MCTS synthesis failed")
      }
      const data = await resp.json()
      setDiscoveries(data.discoveries || [])
    } catch (err) {
      console.error(err)
      setErrorMsg("Failed to execute MCTS simulations.")
    } finally {
      setSynthesizing(false)
    }
  }

  return (
    <div className="flex flex-col gap-6 p-6" style={{ background: "#060B14", color: "#E8F0FE" }}>
      {/* Header */}
      <div className="flex items-center justify-between border-b pb-4" style={{ borderColor: "#1E3349" }}>
        <div>
          <div className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-[#FF6B00]" />
            <h1 className="text-xl font-bold tracking-wider font-mono">KALI-PRIME // PROACTIVE ADVERSARY PATH SYNTHESIS (ANPS)</h1>
          </div>
          <p className="text-xs text-[#6B85A8] mt-1 font-mono">
            Real Monte Carlo Tree Search (MCTS, 500 iterations) over MITRE Group G0134 graph identifying defensive gaps
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            disabled={synthesizing}
            onClick={handleRunMCTS}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#FF6B00] text-black hover:opacity-90 font-mono text-xs font-bold transition-opacity disabled:opacity-50"
          >
            <Cpu className={`w-3.5 h-3.5 ${synthesizing ? "animate-spin" : ""}`} />
            <span>{synthesizing ? "RUNNING MCTS..." : "EXECUTE ANPS (500 MCTS)"}</span>
          </button>
          <button
            onClick={fetchDiscoveries}
            className="p-1.5 border border-[#1E3349] hover:bg-[#0D1521] text-[#6B85A8]"
            title="Refresh Discoveries"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="p-3 bg-[#FF3B30]/10 border border-[#FF3B30] text-[#FF3B30] text-xs font-mono flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Discoveries List */}
      <div className="flex flex-col gap-4">
        {discoveries.length === 0 && !loading ? (
          <div className="p-12 border border-dashed border-[#1E3349] text-center font-mono text-xs text-[#6B85A8]">
            NO MCTS DISCOVERIES CACHED. CLICK 'EXECUTE ANPS' TO RUN 500 MONTE CARLO TREE SEARCH SIMULATIONS.
          </div>
        ) : (
          discoveries.map((disc) => {
            const isGap = disc.gap_status === "DEFENSIVE_GAP"
            const isUncalibrated = disc.detection_uncalibrated

            return (
              <div
                key={disc.discovery_id}
                className="border p-5 flex flex-col justify-between font-mono text-xs bg-[#0D1521]"
                style={{ borderColor: isGap ? "#FF9500" : "#1E3349" }}
              >
                <div>
                  <div className="flex items-center justify-between border-b pb-2 mb-3" style={{ borderColor: "#1E3349" }}>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-[#E8F0FE] text-sm">{disc.discovery_id}</span>
                      {isUncalibrated && (
                        <span className="px-2 py-0.5 font-bold text-[#FFCC00] border border-[#FFCC00] bg-[#FFCC00]/10 text-[10px]">
                          ⚠ UNCALIBRATED — INSUFFICIENT BASELINE DATA
                        </span>
                      )}
                    </div>

                    {isGap ? (
                      <span className="px-2 py-0.5 font-bold text-[#FF9500] border border-[#FF9500] bg-[#FF9500]/10 flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3" /> DEFENSIVE GAP
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 font-bold text-[#34C759] border border-[#34C759] bg-[#34C759]/10 flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" /> COVERED
                      </span>
                    )}
                  </div>

                  <div className="flex flex-col gap-2">
                    <div>
                      <span className="text-[#6B85A8]">Candidate Attack Sequence (MCTS Trajectory):</span>
                      <div className="flex flex-wrap gap-2 mt-1.5">
                        {disc.technique_sequence?.map((tech, idx) => (
                          <div key={idx} className="flex items-center gap-1.5">
                            <span className="px-2.5 py-1 bg-[#060B14] border border-[#1E3349] text-[#E8F0FE] font-bold">
                              {tech}
                            </span>
                            {idx < disc.technique_sequence.length - 1 && (
                              <span className="text-[#6B85A8]">→</span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-2">
                      <div>
                        <span className="text-[#6B85A8]">Adversary Utility:</span>{" "}
                        <span className="text-[#FF6B00] font-bold">{disc.adversary_utility?.toFixed(4)}</span>
                      </div>
                      <div>
                        <span className="text-[#6B85A8]">Estimated P(Detection):</span>{" "}
                        <span className="text-[#E8F0FE] font-bold">{disc.p_detection?.toFixed(4)}</span>
                      </div>
                      <div>
                        <span className="text-[#6B85A8]">APT36 Preference Weight:</span>{" "}
                        <span className="text-[#5AC8FA] font-bold">{disc.brahma_preference_score?.toFixed(2)}</span>
                      </div>
                    </div>

                    <div className="mt-2 text-[#6B85A8] border-t pt-2" style={{ borderColor: "#1E3349" }}>
                      <span className="text-[#E8F0FE] font-semibold">Hardening Recommendation:</span>{" "}
                      <span className={isGap ? "text-[#FF9500]" : "text-[#6B85A8]"}>
                        {disc.hardening_recommendation}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
