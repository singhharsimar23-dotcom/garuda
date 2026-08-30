import React, { useState, useEffect } from "react"
import { ShieldCheck, XOctagon, Clock, AlertCircle } from "lucide-react"

const INITIAL_PENDING_ACTIONS = [
  {
    action_id: "act-iso-9941a8",
    action_type: "PROCESS_ISOLATION",
    tier: 1,
    agent_id: "delhi-core-gw",
    target_pid: 4521,
    target_comm: "payload_worker",
    ias_score: 5.42,
    evidence_summary: "Physical power divergence + severe L3 cache miss spike (T1055.012).",
    time_remaining_sec: 720,
    status: "PENDING_APPROVAL",
  },
  {
    action_id: "act-sinkhole-33d1e2",
    action_type: "DNS_SINKHOLE",
    tier: 0,
    agent_id: "delhi-core-gw",
    target_pid: null,
    target_comm: "c2.nic-gov.in",
    ias_score: 5.42,
    evidence_summary: "Automated sinkhole executed for verified malicious STIX C2 domain.",
    time_remaining_sec: 0,
    status: "AUTO_EXECUTED",
  },
]

export default function AuthorizationQueue() {
  const [actions, setActions] = useState(INITIAL_PENDING_ACTIONS)

  useEffect(() => {
    const timer = setInterval(() => {
      setActions((prev) =>
        prev.map((act) => {
          if (act.status === "PENDING_APPROVAL" && act.time_remaining_sec > 0) {
            const nextTime = act.time_remaining_sec - 1
            return {
              ...act,
              time_remaining_sec: nextTime,
              status: nextTime <= 0 ? "AUTO_ESCALATED" : "PENDING_APPROVAL",
            }
          }
          return act
        })
      )
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  const handleDecision = (actionId, decision) => {
    setActions((prev) =>
      prev.map((act) => {
        if (act.action_id === actionId) {
          return {
            ...act,
            status: decision === "APPROVE" ? "APPROVED_EXECUTED" : "REJECTED",
          }
        }
        return act
      })
    )
  }

  const formatCountdown = (seconds) => {
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
            <h1 className="text-xl font-bold tracking-wider font-mono">DHARMA // OPERATOR AUTHORIZATION QUEUE</h1>
          </div>
          <p className="text-xs text-[#6B85A8] mt-1 font-mono">
            Tier 1 containment interventions awaiting human approval with 15-minute SLA countdown and auto-escalation
          </p>
        </div>
      </div>

      {/* Action Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {actions.map((act) => {
          const isPending = act.status === "PENDING_APPROVAL"
          const isEscalated = act.status === "AUTO_ESCALATED"

          return (
            <div
              key={act.action_id}
              className={`border p-5 flex flex-col justify-between font-mono text-xs ${
                isEscalated ? "opacity-60 bg-[#0D1521]/60" : "bg-[#0D1521]"
              }`}
              style={{ borderColor: isPending ? "#FF6B00" : "#1E3349" }}
            >
              <div>
                <div className="flex items-center justify-between border-b pb-2 mb-3" style={{ borderColor: "#1E3349" }}>
                  <span className="font-bold text-[#E8F0FE] text-sm uppercase">{act.action_type}</span>
                  {isPending ? (
                    <div className="flex items-center gap-1.5 text-[#FF6B00] font-bold">
                      <Clock className="w-3.5 h-3.5" />
                      <span>{formatCountdown(act.time_remaining_sec)}</span>
                    </div>
                  ) : (
                    <span
                      className={`px-2 py-0.5 font-bold ${
                        act.status === "APPROVED_EXECUTED"
                          ? "text-[#34C759] border border-[#34C759]"
                          : act.status === "AUTO_EXECUTED"
                          ? "text-[#34C759] border border-[#34C759]"
                          : act.status === "AUTO_ESCALATED"
                          ? "text-[#FF3B30] border border-[#FF3B30]"
                          : "text-[#6B85A8] border border-[#6B85A8]"
                      }`}
                    >
                      {act.status}
                    </span>
                  )}
                </div>

                <div className="flex flex-col gap-2 text-[#6B85A8]">
                  <div>
                    <span className="text-[#E8F0FE]">Host:</span> {act.agent_id}
                  </div>
                  {act.target_pid && (
                    <div>
                      <span className="text-[#E8F0FE]">Target Process:</span> PID {act.target_pid} ({act.target_comm})
                    </div>
                  )}
                  <div>
                    <span className="text-[#E8F0FE]">Physical Evidence:</span> {act.evidence_summary}
                  </div>
                  <div>
                    <span className="text-[#E8F0FE]">IAS Score:</span>{" "}
                    <span className="text-[#FF3B30] font-bold">{act.ias_score.toFixed(2)} σ</span>
                  </div>
                </div>
              </div>

              {isPending && (
                <div className="mt-5 pt-3 border-t flex gap-2" style={{ borderColor: "#1E3349" }}>
                  <button
                    onClick={() => handleDecision(act.action_id, "APPROVE")}
                    className="flex-1 py-2 bg-[#FF6B00] text-black font-bold text-xs hover:opacity-90 transition-opacity"
                  >
                    APPROVE (SIGSTOP)
                  </button>
                  <button
                    onClick={() => handleDecision(act.action_id, "REJECT")}
                    className="px-4 py-2 border text-[#6B85A8] hover:bg-[#1E3349] transition-colors"
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
    </div>
  )
}
