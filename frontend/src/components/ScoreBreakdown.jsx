import React, { useState } from "react"

const SIGNAL_LABELS = {
  homoglyph: { label: "Homoglyph Lookalike", color: "bg-red-500", weight: 30 },
  nic_similarity: { label: "NIC Gov Similarity", color: "bg-orange-500", weight: 25 },
  keyword_matches: { label: "Tier-1 Defence Keywords", color: "bg-amber-500", weight: 20 },
  registrar: { label: "APT36 Registrar Affinity", color: "bg-yellow-500", weight: 15 },
  asn: { label: "APT36 ASN Infrastructure", color: "bg-emerald-500", weight: 25 },
  c2_ports: { label: "Shodan C2 Exposed Ports", color: "bg-cyan-500", weight: 20 },
  dga_score: { label: "DGA ML Classifier", color: "bg-purple-500", weight: 15 },
  honeypot_hit: { label: "Decoy Honeypot Recon Hit", color: "bg-rose-600", weight: 35 },
}

export default function ScoreBreakdown({ score = 0, signals = {} }) {
  const [hoveredSignal, setHoveredSignal] = useState(null)

  // Calculate active signal segments
  const activeSegments = []
  let totalCalculated = 0

  if (signals.has_homoglyph) {
    activeSegments.push({ key: "homoglyph", ...SIGNAL_LABELS.homoglyph, value: 30 })
    totalCalculated += 30
  }
  if (signals.nic_similarity > 0.6) {
    const val = Math.round(signals.nic_similarity * 25)
    activeSegments.push({ key: "nic_similarity", ...SIGNAL_LABELS.nic_similarity, value: val })
    totalCalculated += val
  }
  if (signals.tier1_matches && signals.tier1_matches.length > 0) {
    const val = Math.min(25, signals.tier1_matches.length * 10)
    activeSegments.push({ key: "keyword_matches", ...SIGNAL_LABELS.keyword_matches, value: val })
    totalCalculated += val
  }
  if (signals.registrar_risk || signals.registrar_flagged) {
    activeSegments.push({ key: "registrar", ...SIGNAL_LABELS.registrar, value: 15 })
    totalCalculated += 15
  }
  if (signals.asn_match || signals.hosting_asn) {
    activeSegments.push({ key: "asn", ...SIGNAL_LABELS.asn, value: 20 })
    totalCalculated += 20
  }
  if (signals.c2_ports_open && signals.c2_ports_open.length > 0) {
    activeSegments.push({ key: "c2_ports", ...SIGNAL_LABELS.c2_ports, value: 20 })
    totalCalculated += 20
  }
  if (signals.is_dga || (signals.dga_prob && signals.dga_prob > 0.5)) {
    activeSegments.push({ key: "dga_score", ...SIGNAL_LABELS.dga_score, value: 15 })
    totalCalculated += 15
  }
  if (signals.honeypot_match) {
    activeSegments.push({ key: "honeypot_hit", ...SIGNAL_LABELS.honeypot_hit, value: 35 })
    totalCalculated += 35
  }

  // Fallback if no specific signals mapped
  if (activeSegments.length === 0 && score > 0) {
    activeSegments.push({
      key: "baseline",
      label: "Composite Threat Vector",
      color: "bg-blue-500",
      value: score,
    })
    totalCalculated = score
  }

  const scoreColor =
    score >= 85 ? "text-red-500 border-red-500/40 bg-red-500/10"
    : score >= 70 ? "text-orange-500 border-orange-500/40 bg-orange-500/10"
    : score >= 40 ? "text-yellow-500 border-yellow-500/40 bg-yellow-500/10"
    : "text-emerald-500 border-emerald-500/40 bg-emerald-500/10"

  return (
    <div className="bg-navy-900 border border-navy-700 rounded-xl p-5 shadow-xl">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">Composite Threat Index</h3>
          <p className="text-xs text-gray-400">Multi-Signal Probabilistic Scoring Matrix</p>
        </div>
        <div className={`px-4 py-1.5 rounded-lg border text-xl font-black font-mono ${scoreColor}`}>
          {score}<span className="text-xs font-normal opacity-70">/100</span>
        </div>
      </div>

      {/* Horizontal Stacked Bar */}
      <div className="relative w-full h-4 bg-navy-950 rounded-full overflow-hidden flex border border-navy-700 shadow-inner">
        {activeSegments.map((seg) => {
          const widthPct = Math.max(5, (seg.value / (totalCalculated || 100)) * 100)
          return (
            <div
              key={seg.key}
              style={{ width: `${widthPct}%` }}
              className={`${seg.color} h-full transition-all duration-300 cursor-pointer hover:brightness-125`}
              onMouseEnter={() => setHoveredSignal(seg)}
              onMouseLeave={() => setHoveredSignal(null)}
            />
          )
        })}
      </div>

      {/* Hover Info / Legend */}
      <div className="mt-3 min-h-[40px] flex items-center justify-between text-xs text-gray-300">
        {hoveredSignal ? (
          <div className="flex items-center space-x-2 animate-fade-in">
            <span className={`w-3 h-3 rounded-full ${hoveredSignal.color}`} />
            <span className="font-semibold text-white">{hoveredSignal.label}:</span>
            <span className="font-mono text-cyan-400">+{hoveredSignal.value} pts</span>
          </div>
        ) : (
          <span className="text-gray-500 italic text-[11px]">Hover over segments to inspect feature contributions</span>
        )}

        <div className="flex flex-wrap gap-2 text-[10px] text-gray-400">
          {activeSegments.slice(0, 4).map((s) => (
            <div key={s.key} className="flex items-center space-x-1">
              <span className={`w-2 h-2 rounded-full ${s.color}`} />
              <span>{s.label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
