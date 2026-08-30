import React, { useState } from "react"
import { ShieldAlert, Crosshair, HelpCircle } from "lucide-react"

const MOCK_ASSESSMENT = {
  agent_id: "delhi-core-gw",
  actor_id: "APT36",
  map_tactic: "execution",
  predicted_next_tactic: "defense-evasion",
  confidence: 0.78,
  observation_count: 22,
  convergence_status: "CONVERGED",
  entropy_bits: 1.42,
  posterior: {
    "reconnaissance": 0.02,
    "resource-development": 0.01,
    "initial-access": 0.05,
    "execution": 0.45,
    "persistence": 0.08,
    "privilege-escalation": 0.04,
    "defense-evasion": 0.22,
    "credential-access": 0.03,
    "discovery": 0.04,
    "lateral-movement": 0.02,
    "collection": 0.01,
    "command-and-control": 0.02,
    "exfiltration": 0.005,
    "impact": 0.005,
  },
}

export default function ThreatAssessment() {
  const [assessment] = useState(MOCK_ASSESSMENT)

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
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-mono text-xs">
        <div className="border p-4" style={{ background: "#0D1521", borderColor: "#1E3349" }}>
          <div className="text-[#6B85A8] mb-1">ATTRIBUTED ACTOR</div>
          <div className="text-lg font-bold text-[#FF6B00]">{assessment.actor_id}</div>
          <div className="text-[#6B85A8] mt-1">Transparent Tribe / PROJECTM</div>
        </div>

        <div className="border p-4" style={{ background: "#0D1521", borderColor: "#1E3349" }}>
          <div className="text-[#6B85A8] mb-1">MAP CURRENT TACTIC</div>
          <div className="text-lg font-bold text-[#E8F0FE] uppercase">{assessment.map_tactic}</div>
          <div className="text-[#6B85A8] mt-1">{(assessment.posterior[assessment.map_tactic] * 100).toFixed(1)}% Posterior Mass</div>
        </div>

        <div className="border p-4" style={{ background: "#0D1521", borderColor: "#1E3349" }}>
          <div className="text-[#6B85A8] mb-1">PREDICTED NEXT STEP</div>
          <div className="text-lg font-bold text-[#FFD60A] uppercase">{assessment.predicted_next_tactic}</div>
          <div className="text-[#6B85A8] mt-1">Transition Graph Prediction</div>
        </div>

        <div className="border p-4" style={{ background: "#0D1521", borderColor: "#1E3349" }}>
          <div className="text-[#6B85A8] mb-1">BAYESIAN CONVERGENCE</div>
          <div className="text-lg font-bold text-[#34C759]">{assessment.convergence_status}</div>
          <div className="text-[#6B85A8] mt-1">{assessment.observation_count} Anomaly Events (Entropy: {assessment.entropy_bits} bits)</div>
        </div>
      </div>

      {/* Kill Chain 14-Tactic Distribution */}
      <div className="border p-6" style={{ background: "#0D1521", borderColor: "#1E3349" }}>
        <div className="text-xs font-mono text-[#6B85A8] uppercase tracking-wider mb-6 flex justify-between">
          <span>Discrete Kill Chain Posterior Distribution P(Tactic | Evidence)</span>
          <span className="text-[#FF6B00]">Total Posterior Sum = 1.000</span>
        </div>

        <div className="flex flex-col gap-3 font-mono text-xs">
          {Object.entries(assessment.posterior).map(([tactic, prob]) => {
            const isMap = tactic === assessment.map_tactic
            const isNext = tactic === assessment.predicted_next_tactic
            const pct = (prob * 100).toFixed(1)

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
                      width: `${pct}%`,
                      background: isMap ? "#FF6B00" : isNext ? "#FFD60A" : "#1E3349",
                    }}
                  />
                  <span className="absolute right-2 top-0.5 text-[10px] text-[#6B85A8] font-bold">
                    {pct}%
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
