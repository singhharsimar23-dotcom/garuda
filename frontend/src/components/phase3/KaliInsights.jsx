import React from "react"
import { Shield, Sparkles, CheckCircle2, AlertTriangle } from "lucide-react"

const MOCK_KALI_DISCOVERIES = [
  {
    id: "kali-disc-8a91f2",
    technique_seq: ["T1566.001 (Phishing)", "T1059.005 (VBScript)", "T1055.012 (Process Hollowing)", "T1071.001 (Web C2)"],
    utility_score: 0.88,
    est_detection_prob: 0.42,
    is_gap: true,
    recommendation: "Deploy EPPI kprobe filter for T1059.005 and monitor reflective DLL injections.",
  },
  {
    id: "kali-disc-4b10c8",
    technique_seq: ["T1190 (Exploit)", "T1059.004 (Unix Shell)", "T1055.001 (Dynamic Injection)", "T1041 (Exfiltration)"],
    utility_score: 0.74,
    est_detection_prob: 0.68,
    is_gap: false,
    recommendation: "Baseline power model successfully captures shell execution bursts.",
  },
]

export default function KaliInsights() {
  return (
    <div className="flex flex-col gap-6 p-6" style={{ background: "#060B14", color: "#E8F0FE" }}>
      {/* Header */}
      <div className="flex items-center justify-between border-b pb-4" style={{ borderColor: "#1E3349" }}>
        <div>
          <div className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-[#FF6B00]" />
            <h1 className="text-xl font-bold tracking-wider font-mono">KALI-PRIME // PROACTIVE ADVERSARY SIMULATION</h1>
          </div>
          <p className="text-xs text-[#6B85A8] mt-1 font-mono">
            Autonomous Novel Path Synthesis (ANPS) identifying defense coverage gaps and pre-populating DHARMA response caches
          </p>
        </div>
      </div>

      {/* Discoveries List */}
      <div className="flex flex-col gap-4">
        {MOCK_KALI_DISCOVERIES.map((disc) => (
          <div
            key={disc.id}
            className="border p-5 flex flex-col justify-between font-mono text-xs"
            style={{ background: "#0D1521", borderColor: "#1E3349" }}
          >
            <div>
              <div className="flex items-center justify-between border-b pb-2 mb-3" style={{ borderColor: "#1E3349" }}>
                <span className="font-bold text-[#E8F0FE]">{disc.id}</span>
                {disc.is_gap ? (
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
                  <span className="text-[#6B85A8]">Candidate Attack Sequence:</span>
                  <div className="flex flex-wrap gap-2 mt-1.5">
                    {disc.technique_seq.map((t, idx) => (
                      <span key={idx} className="px-2 py-1 bg-[#060B14] border border-[#1E3349] text-[#E8F0FE] font-bold">
                        {t}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 mt-2">
                  <div>
                    <span className="text-[#6B85A8]">Adversary Utility:</span>{" "}
                    <span className="text-[#FF6B00] font-bold">{(disc.utility_score * 100).toFixed(1)}%</span>
                  </div>
                  <div>
                    <span className="text-[#6B85A8]">Estimated P(Detection):</span>{" "}
                    <span className="text-[#E8F0FE] font-bold">{(disc.est_detection_prob * 100).toFixed(1)}%</span>
                  </div>
                </div>

                <div className="mt-2 text-[#6B85A8] border-t pt-2" style={{ borderColor: "#1E3349" }}>
                  <span className="text-[#E8F0FE] font-semibold">Hardening Recommendation:</span> {disc.recommendation}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
