import React, { useState, useEffect, useCallback } from "react"
import { ShieldAlert, Crosshair, HelpCircle, RefreshCw, AlertCircle } from "lucide-react"

const API_BASE = import.meta.env.VITE_BRAHMA_API_URL || "https://garuda-brahma-service.onrender.com"

export default function ThreatAssessment() {
  const [assessment, setAssessment] = useState(null)
  const [loading, setLoading] = useState(true)
  const [errorMsg, setErrorMsg] = useState(null)

  const fetchLiveState = useCallback(async () => {
    setLoading(true)
    setErrorMsg(null)
    try {
      // Query live attribution state from BRAHMA engine
      const resp = await fetch(`${API_BASE}/api/v1/brahma/state/active`)
      if (resp.ok) {
        const data = await resp.json()
        if (data && data.posterior) {
          setAssessment(data)
        } else {
          setAssessment(null)
        }
      } else if (resp.status === 404) {
        setAssessment(null)
      } else {
        setErrorMsg(`BRAHMA returned HTTP ${resp.status}`)
      }
    } catch (err) {
      console.warn("Unable to connect to BRAHMA:", err)
      setErrorMsg("Unable to connect to BRAHMA attribution engine.")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchLiveState()
    const interval = setInterval(fetchLiveState, 10000)
    return () => clearInterval(interval)
  }, [fetchLiveState])

  return (
    <div className="flex flex-col gap-6 p-6" style={{ background: "#060B14", color: "#E8F0FE" }}>
      {/* Header */}
      <div className="flex items-center justify-between border-b pb-4" style={{ borderColor: "#1E3349" }}>
        <div>
          <div className="flex items-center gap-2">
            <Crosshair className="w-5 h-5 text-[#FF6B00]" />
            <h1 className="text-xl font-bold tracking-wider font-mono">BRAHMA // ADVERSARY PROGRAM & KILL CHAIN MODEL</h1>
          </div>
          <p className="text-xs text-[#6B85A8] mt-1 font-mono">
            Online Bayesian update over 14 MITRE ATT&CK tactics with strict Rule 8 attribution gating (≥15 observations)
          </p>
        </div>
        <button
          onClick={fetchLiveState}
          className="flex items-center gap-2 px-3 py-1.5 border text-xs font-mono transition-colors hover:bg-[#1E3349]"
          style={{ borderColor: "#1E3349", color: "#6B85A8" }}
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-[#FF6B00]" : ""}`} />
          <span>SYNC 10s</span>
        </button>
      </div>

      {errorMsg && (
        <div className="flex items-center gap-2 p-3 border bg-[#FF3B30]/10 border-[#FF3B30] text-[#FF3B30] font-mono text-xs">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* When no live model is active */}
      {!assessment ? (
        <div className="border p-12 text-center text-[#6B85A8] font-mono text-xs" style={{ background: "#0D1521", borderColor: "#1E3349" }}>
          {loading
            ? "CONNECTING TO BRAHMA ADVERSARY MODEL..."
            : "NO ATTRIBUTED ADVERSARY CAMPAIGN ACTIVE. REQUIRES ≥15 CORROBORATED PHYSICAL ANOMALIES TO TRIGGER ATTRIBUTION GATING."}
        </div>
      ) : (
        <>
          {/* Overview Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-mono text-xs">
            <div className="border p-4" style={{ background: "#0D1521", borderColor: "#1E3349" }}>
              <div className="text-[#6B85A8] mb-1">ATTRIBUTED ACTOR</div>
              <div className="text-lg font-bold text-[#FF6B00]">{assessment.actor_id || "UNATTRIBUTED"}</div>
              <div className="text-[#6B85A8] mt-1">{assessment.attribution_status || "Evaluating evidence..."}</div>
            </div>

            <div className="border p-4" style={{ background: "#0D1521", borderColor: "#1E3349" }}>
              <div className="text-[#6B85A8] mb-1">MAP CURRENT TACTIC</div>
              <div className="text-lg font-bold text-[#E8F0FE] uppercase">{assessment.map_tactic || "NONE"}</div>
              <div className="text-[#6B85A8] mt-1">
                {assessment.posterior && assessment.map_tactic ? Number(assessment.posterior[assessment.map_tactic] || 0).toFixed(4) : "0.0000"} Posterior Mass
              </div>
            </div>

            <div className="border p-4" style={{ background: "#0D1521", borderColor: "#1E3349" }}>
              <div className="text-[#6B85A8] mb-1">PREDICTED NEXT STEP</div>
              <div className="text-lg font-bold text-[#FFD60A] uppercase">{assessment.predicted_next_tactic || "MONITORING"}</div>
              <div className="text-[#6B85A8] mt-1">Transition Graph Prediction</div>
            </div>

            <div className="border p-4" style={{ background: "#0D1521", borderColor: "#1E3349" }}>
              <div className="text-[#6B85A8] mb-1">EVIDENCE CHAIN</div>
              <div className="text-lg font-bold text-[#34C759]">{assessment.observation_count || 0} Observations</div>
              <div className="text-[#6B85A8] mt-1">Entropy: {Number(assessment.entropy_bits || 0).toFixed(2)} bits</div>
            </div>
          </div>

          {/* Kill Chain 14-Tactic Distribution */}
          {assessment.posterior && (
            <div className="border p-6" style={{ background: "#0D1521", borderColor: "#1E3349" }}>
              <div className="text-xs font-mono text-[#6B85A8] uppercase tracking-wider mb-6 flex justify-between">
                <span>Discrete Kill Chain Posterior Distribution P(Tactic | Evidence)</span>
                <span className="text-[#FF6B00]">Total Posterior Sum = 1.000</span>
              </div>

              <div className="flex flex-col gap-3 font-mono text-xs">
                {Object.entries(assessment.posterior).map(([tactic, prob]) => {
                  const isMap = tactic === assessment.map_tactic
                  const isNext = tactic === assessment.predicted_next_tactic
                  const massStr = Number(prob).toFixed(4)

                  return (
                    <div key={tactic} className="flex items-center gap-4">
                      <div className="w-48 text-right font-medium text-[#E8F0FE] uppercase flex items-center justify-end gap-1.5">
                        {isMap && <span className="w-2 h-2 rounded-full bg-[#FF6B00]" />}
                        {isNext && <span className="w-2 h-2 rounded-full bg-[#FFD60A]" />}
                        <span>{tactic}</span>
                      </div>

                      <div className="flex-1 bg-[#060B14] h-5 border relative overflow-hidden" style={{ borderColor: "#1E3349" }}>
                        <div
                          className="h-full transition-all duration-300"
                          style={{
                            width: `${(Number(prob) * 100).toFixed(1)}%`,
                            background: isMap ? "#FF6B00" : isNext ? "#FFD60A" : "#1E3349",
                          }}
                        />
                      </div>

                      <div className="w-24 font-data text-right text-[#6B85A8]">
                        <span className={isMap ? "text-[#FF6B00] font-bold" : "text-[#E8F0FE]"}>{massStr} mass</span>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
