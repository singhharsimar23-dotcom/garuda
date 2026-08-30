import React, { useState, useEffect, useCallback } from "react"
import { ShieldCheck, XOctagon, Clock, AlertCircle, RefreshCw, CheckCircle2, AlertTriangle } from "lucide-react"

const API_BASE = import.meta.env.VITE_BRAHMA_API_URL || "https://garuda-brahma.onrender.com"

export default function AuthorizationQueue() {
  const [actions, setActions] = useState([])
  const [loading, setLoading] = useState(true)
  const [ttls, setTtls] = useState({})
  const [processingId, setProcessingId] = useState(null)
  const [errorMsg, setErrorMsg] = useState(null)

  // Fetch real actions from dharma_action_log
  const fetchActions = useCallback(async () => {
    try {
      const resp = await fetch(`${API_BASE}/api/v1/dharma/actions?limit=25`)
      if (resp.ok) {
        const data = await resp.json()
        const fetched = data.actions || []
        setActions(fetched)

        // Fetch TTL for queued actions
        fetched.forEach(async (act) => {
          if (act.status === "QUEUED" || act.status === "QUEUED_EMERGENCY_APPROVAL") {
            try {
              const ttlResp = await fetch(`${API_BASE}/api/v1/dharma/ttl/${act.action_id}`)
              if (ttlResp.ok) {
                const ttlData = await ttlResp.json()
                setTtls((prev) => ({ ...prev, [act.action_id]: ttlData.ttl_seconds }))
              }
            } catch (err) {
              console.debug("TTL fetch failed", err)
            }
          }
        })
      }
    } catch (err) {
      console.warn("Failed fetching DHARMA actions", err)
      setErrorMsg("Could not connect to DHARMA execution service.")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchActions()
    const interval = setInterval(fetchActions, 4000)
    return () => clearInterval(interval)
  }, [fetchActions])

  // SLA countdown ticker based on Redis TTL
  useEffect(() => {
    const timer = setInterval(() => {
      setTtls((prev) => {
        const updated = { ...prev }
        Object.keys(updated).forEach((id) => {
          if (updated[id] > 0) {
            updated[id] -= 1
          }
        })
        return updated
      })
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  const handleDecision = async (actionId, decision) => {
    setProcessingId(actionId)
    setErrorMsg(null)
    try {
      const endpoint = decision === "APPROVE" 
        ? `${API_BASE}/api/v1/dharma/approve/${actionId}` 
        : `${API_BASE}/api/v1/dharma/reject/${actionId}`

      const resp = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operator_id: "operator_web_ui" }),
      })

      if (!resp.ok) {
        const errData = await resp.json()
        throw new Error(errData.detail || "Action failed")
      }

      await fetchActions()
    } catch (err) {
      console.error(`Decision error: ${err.message}`)
      setErrorMsg(`Execution error for ${actionId}: ${err.message}`)
    } finally {
      setProcessingId(null)
    }
  }

  const formatCountdown = (seconds) => {
    if (seconds === undefined || seconds < 0) return "EXPIRED"
    const mins = Math.floor(seconds / 60)
    const secs = seconds % 60
    return `${mins}:${secs < 10 ? "0" : ""}${secs}`
  }

  return (
    <div className="flex flex-col gap-6 p-6" style={{ background: "#060B14", color: "#E8F0FE" }}>
      {/* Header */}
      <div className="flex items-center justify-between border-b pb-4" style={{ borderColor: "#1E3349" }}>
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-[#FF6B00]" />
            <h1 className="text-xl font-bold tracking-wider font-mono">DHARMA // OPERATOR AUTHORIZATION & EXECUTION QUEUE</h1>
          </div>
          <p className="text-xs text-[#6B85A8] mt-1 font-mono">
            Real containment execution via paramiko SSH (SIGSTOP) and Cloudflare DNS v4 sinkholing with Redis SLA tracking
          </p>
        </div>
        <button
          onClick={fetchActions}
          className="flex items-center gap-1.5 px-3 py-1.5 border border-[#1E3349] hover:bg-[#0D1521] text-xs font-mono text-[#6B85A8]"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>REFRESH</span>
        </button>
      </div>

      {errorMsg && (
        <div className="p-3 bg-[#FF3B30]/10 border border-[#FF3B30] text-[#FF3B30] text-xs font-mono flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Action Cards */}
      {actions.length === 0 && !loading ? (
        <div className="p-12 border border-dashed border-[#1E3349] text-center font-mono text-xs text-[#6B85A8]">
          NO ACTIVE CONTAINMENT ACTIONS IN QUEUE. MONITORING SENSOR TELEMETRY.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {actions.map((act) => {
            const isPending = act.status === "QUEUED" || act.status === "QUEUED_EMERGENCY_APPROVAL"
            const isAutoExecuted = act.status === "EXECUTED" && act.tier === 2
            const isExecuted = act.status === "EXECUTED" && act.tier !== 2
            const isFailed = act.status === "FAILED"
            const isStale = act.status === "STALE_PID"
            const isAlreadyApplied = act.status === "ALREADY_APPLIED"
            const isRejected = act.status === "REJECTED"
            const isProcessing = processingId === act.action_id

            const remainingSeconds = ttls[act.action_id]

            return (
              <div
                key={act.action_id}
                className="border p-5 flex flex-col justify-between font-mono text-xs bg-[#0D1521]"
                style={{ borderColor: isPending ? (act.tier === 3 ? "#FF3B30" : "#FF6B00") : "#1E3349" }}
              >
                <div>
                  <div className="flex items-center justify-between border-b pb-2 mb-3" style={{ borderColor: "#1E3349" }}>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-[#E8F0FE] text-sm uppercase">{act.action_type}</span>
                      <span className="text-[10px] px-1.5 py-0.5 bg-[#1E3349] text-[#6B85A8]">TIER {act.tier}</span>
                    </div>

                    {isPending ? (
                      <div className="flex items-center gap-1.5 text-[#FF6B00] font-bold">
                        <Clock className="w-3.5 h-3.5" />
                        <span>{formatCountdown(remainingSeconds)}</span>
                      </div>
                    ) : (
                      <span
                        className={`px-2 py-0.5 font-bold ${
                          isAutoExecuted
                            ? "text-[#34C759] border border-[#34C759] bg-[#34C759]/10"
                            : isExecuted
                            ? "text-[#34C759] border border-[#34C759]"
                            : isFailed
                            ? "text-[#FF3B30] border border-[#FF3B30] bg-[#FF3B30]/10"
                            : isStale
                            ? "text-[#FFCC00] border border-[#FFCC00]"
                            : isAlreadyApplied
                            ? "text-[#5AC8FA] border border-[#5AC8FA]"
                            : isRejected
                            ? "text-[#6B85A8] border border-[#6B85A8]"
                            : "text-[#6B85A8] border border-[#6B85A8]"
                        }`}
                      >
                        {isAutoExecuted ? "AUTO_EXECUTED" : act.status}
                      </span>
                    )}
                  </div>

                  <div className="flex flex-col gap-2 text-[#6B85A8]">
                    <div>
                      <span className="text-[#E8F0FE]">Action ID:</span> <span className="text-[#5AC8FA]">{act.action_id}</span>
                    </div>
                    <div>
                      <span className="text-[#E8F0FE]">Host:</span> {act.hostname}
                    </div>
                    <div>
                      <span className="text-[#E8F0FE]">Target:</span> <span className="text-[#FF6B00] font-bold">{act.target}</span>
                    </div>
                    {act.ias_score_at_trigger && (
                      <div>
                        <span className="text-[#E8F0FE]">Trigger IAS:</span>{" "}
                        <span className="text-[#FF3B30] font-bold">{act.ias_score_at_trigger.toFixed(2)} σ</span>
                      </div>
                    )}
                    {act.operator_id && (
                      <div>
                        <span className="text-[#E8F0FE]">Operator:</span> {act.operator_id}
                      </div>
                    )}
                    {act.executed_at && (
                      <div>
                        <span className="text-[#E8F0FE]">Executed At:</span> {new Date(act.executed_at).toLocaleTimeString()}
                      </div>
                    )}
                  </div>
                </div>

                {isPending && (
                  <div className="mt-5 pt-3 border-t flex gap-2" style={{ borderColor: "#1E3349" }}>
                    <button
                      disabled={isProcessing}
                      onClick={() => handleDecision(act.action_id, "APPROVE")}
                      className="flex-1 py-2 bg-[#FF6B00] text-black font-bold text-xs hover:opacity-90 transition-opacity disabled:opacity-50"
                    >
                      {isProcessing ? "EXECUTING..." : act.action_type === "DNS_SINKHOLE" ? "APPROVE (SINKHOLE)" : "APPROVE (SIGSTOP)"}
                    </button>
                    <button
                      disabled={isProcessing}
                      onClick={() => handleDecision(act.action_id, "REJECT")}
                      className="px-4 py-2 border text-[#6B85A8] hover:bg-[#1E3349] transition-colors disabled:opacity-50"
                      style={{ borderColor: "#1E3349" }}
                    >
                      REJECT
                    </button>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
