import React, { useState } from "react"

const SIGNAL_CONTRIBUTIONS = [
  { key: "keyword_score",      label: "Keyword Match",    color: "#FF6B35", maxPts: 30 },
  { key: "nic_similarity",     label: "NIC Similarity",   color: "#FF8C00", maxPts: 20 },
  { key: "tld_score",          label: "TLD Signal",       color: "#FFB300", maxPts: 15 },
  { key: "registrar_score",    label: "Registrar Risk",   color: "#FFC107", maxPts: 10 },
  { key: "geopolitical_boost", label: "Geopolitical",     color: "#FF4081", maxPts: 10 },
  { key: "campaign_cluster",   label: "Campaign Cluster", color: "#E040FB", maxPts: 10 },
  { key: "honeypot_fire",      label: "Honeypot Fire",    color: "#FF1744", maxPts: 5  },
]

export function ThreatScoreBar({ alert = {}, totalScore = 0 }) {
  const [hovered, setHovered] = useState(null)

  const signals = alert?.signals || alert || {}
  const score = totalScore || alert?.score || 0

  // Calculate actual points per signal
  const segments = []
  if (signals.keyword_score || signals.tier1_matches) {
    segments.push({ key: "keyword_score", label: "Keyword Match", color: "#FF6B35", pts: signals.keyword_score || 25 })
  }
  if (signals.nic_similarity && signals.nic_similarity > 0) {
    segments.push({ key: "nic_similarity", label: "NIC Similarity", color: "#FF8C00", pts: Math.round(signals.nic_similarity * 20) })
  }
  if (signals.homoglyph || signals.has_homoglyph) {
    segments.push({ key: "tld_score", label: "Homoglyph/TLD", color: "#FFB300", pts: 20 })
  }
  if (signals.registrar_score || signals.registrar_match) {
    segments.push({ key: "registrar_score", label: "Registrar Risk", color: "#FFC107", pts: signals.registrar_score || 15 })
  }
  if (signals.tension_index && signals.tension_index >= 0.6) {
    segments.push({ key: "geopolitical_boost", label: "Geopolitical Boost", color: "#FF4081", pts: 10 })
  }
  if (signals.asn_match || signals.hosting_asn) {
    segments.push({ key: "campaign_cluster", label: "ASN Infrastructure", color: "#E040FB", pts: 15 })
  }

  // Fallback segment if empty
  if (segments.length === 0 && score > 0) {
    segments.push({ key: "baseline", label: "Base Threat Vector", color: "#FF6B35", pts: score })
  }

  const totalPts = segments.reduce((acc, s) => acc + s.pts, 0) || 100

  return (
    <div className="w-full">
      <div className="flex h-7 rounded overflow-hidden gap-0.5 bg-void border border-border">
        {segments.map((sig) => {
          const pct = Math.max(8, (sig.pts / totalPts) * 100)
          return (
            <div
              key={sig.key}
              style={{
                width: `${pct}%`,
                background: sig.color,
                cursor: "pointer",
                opacity: hovered === sig.key ? 1 : 0.88,
                transition: "all 0.15s ease",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 10,
                color: "#060B14",
                fontWeight: 700,
                fontFamily: "JetBrains Mono, monospace",
                minWidth: sig.pts > 5 ? 28 : 0,
              }}
              onMouseEnter={() => setHovered(sig.key)}
              onMouseLeave={() => setHovered(null)}
            >
              {sig.pts > 8 ? `+${sig.pts}` : ""}
            </div>
          )
        })}
      </div>
      <div className="flex items-center justify-between text-2xs mt-1.5 font-data">
        {hovered ? (
          <div>
            <span className="font-bold" style={{ color: segments.find((s) => s.key === hovered)?.color }}>
              {segments.find((s) => s.key === hovered)?.label}
            </span>
            <span className="text-secondary ml-1.5">
              +{segments.find((s) => s.key === hovered)?.pts} pts
            </span>
          </div>
        ) : (
          <span className="text-ghost">Hover segments to inspect feature contributions</span>
        )}
        <span className="font-bold text-saffron">{score}/100</span>
      </div>
    </div>
  )
}

export default ThreatScoreBar
