import React from "react"

export const getTensionLabel = (score) => {
  const s = Number(score) || 0
  if (s >= 0.80) return { label: "KINETIC", color: "#FF0000", bg: "bg-red-500/20 text-red-400 border-red-500/40" }
  if (s >= 0.65) return { label: "HIGH", color: "#FF4500", bg: "bg-orange-500/20 text-orange-400 border-orange-500/40" }
  if (s >= 0.45) return { label: "ELEVATED", color: "#FF8C00", bg: "bg-amber-500/20 text-amber-400 border-amber-500/40" }
  if (s >= 0.25) return { label: "GUARDED", color: "#FFA500", bg: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40" }
  return { label: "NOMINAL", color: "#00C853", bg: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40" }
}

export default function TensionGauge({ tension = 0.50, conflictMode = false }) {
  const val = typeof tension === "number" ? tension : Number(tension) || 0.50
  const percentage = Math.min(100, Math.max(0, Math.round(val * 100)))
  const tensionInfo = getTensionLabel(val)

  // SVG Arc Calculation (Half-Circle Gauge)
  const radius = 60
  const circumference = Math.PI * radius
  const strokeDashoffset = circumference - (percentage / 100) * circumference
  const color = tensionInfo.color

  return (
    <div className="bg-navy-900 border border-navy-700/80 rounded-xl p-4 shadow-xl flex flex-col items-center justify-center relative overflow-hidden">
      <div className="w-full flex items-center justify-between mb-1">
        <span className="text-[11px] font-bold uppercase tracking-wider text-gray-400">
          Geopolitical Tension
        </span>
        {conflictMode ? (
          <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase bg-red-500/20 text-red-400 border border-red-500/40 animate-pulse">
            Conflict Mode
          </span>
        ) : (
          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase border ${tensionInfo.bg}`}>
            {tensionInfo.label}
          </span>
        )}
      </div>

      <div className="relative flex items-center justify-center my-2">
        <svg className="w-36 h-20" viewBox="0 0 140 80">
          {/* Background Arc */}
          <path
            d="M 10 75 A 60 60 0 0 1 130 75"
            fill="none"
            stroke="#1e293b"
            strokeWidth="12"
            strokeLinecap="round"
          />
          {/* Progress Colored Arc */}
          <path
            d="M 10 75 A 60 60 0 0 1 130 75"
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            className="transition-all duration-700 ease-out"
          />
        </svg>

        <div className="absolute top-8 flex flex-col items-center">
          <span className="text-2xl font-black font-mono tracking-tight" style={{ color }}>
            {percentage}
            <span className="text-xs text-gray-400 font-normal">%</span>
          </span>
        </div>
      </div>

      <div className="w-full flex justify-between text-[9px] text-gray-500 px-3 font-mono">
        <span>0.00 PEACETIME</span>
        <span>1.00 KINETIC</span>
      </div>
    </div>
  )
}
