import React from "react"

export default function StatCard({ title, value, subtitle, icon: Icon, color = "cyan", pulse = false }) {
  const colorMap = {
    red: "text-red-500 border-red-500/30 bg-red-500/5",
    orange: "text-orange-500 border-orange-500/30 bg-orange-500/5",
    emerald: "text-emerald-500 border-emerald-500/30 bg-emerald-500/5",
    cyan: "text-cyan-400 border-cyan-500/30 bg-cyan-500/5",
    blue: "text-blue-400 border-blue-500/30 bg-blue-500/5",
  }

  const activeColorClass = colorMap[color] || colorMap.cyan

  return (
    <div className={`relative overflow-hidden rounded-xl border p-4 shadow-xl transition-all duration-200 hover:scale-[1.01] ${activeColorClass}`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-[11px] font-bold uppercase tracking-wider text-gray-400">{title}</p>
          <h4 className="mt-1 text-2xl font-black font-mono tracking-tight text-white flex items-center gap-2">
            {value}
            {pulse && <span className="w-2 h-2 rounded-full bg-red-500 animate-ping" />}
          </h4>
          {subtitle && <p className="mt-1 text-xs text-gray-400">{subtitle}</p>}
        </div>
        {Icon && (
          <div className="rounded-lg bg-navy-950/60 p-2.5 border border-navy-700/50">
            <Icon className="w-5 h-5 opacity-90" />
          </div>
        )}
      </div>
    </div>
  )
}
