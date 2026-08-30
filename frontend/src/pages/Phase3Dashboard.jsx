import React, { useState } from "react"
import { Zap, Crosshair, FileText, ShieldCheck, Sparkles } from "lucide-react"

import PhysicsMonitor from "../components/phase3/PhysicsMonitor"
import ThreatAssessment from "../components/phase3/ThreatAssessment"
import SitrepPanel from "../components/phase3/SitrepPanel"
import AuthorizationQueue from "../components/phase3/AuthorizationQueue"
import KaliInsights from "../components/phase3/KaliInsights"

const TABS = [
  { id: "axiom", label: "AXIOM (PHYSICS)", icon: Zap },
  { id: "brahma", label: "BRAHMA (ADVERSARY)", icon: Crosshair },
  { id: "sitrep", label: "UTNE (SITREP)", icon: FileText },
  { id: "queue", label: "DHARMA (QUEUE)", icon: ShieldCheck },
  { id: "kali", label: "KALI (SIMULATION)", icon: Sparkles },
]

export default function Phase3Dashboard() {
  const [activeTab, setActiveTab] = useState("axiom")

  return (
    <div className="flex flex-col h-full overflow-y-auto" style={{ background: "#060B14" }}>
      {/* Navigation Tab Bar */}
      <div className="flex border-b px-6 pt-4 gap-2" style={{ borderColor: "#1E3349", background: "#0D1521" }}>
        {TABS.map((tab) => {
          const Icon = tab.icon
          const isActive = activeTab === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-mono font-bold border-b-2 transition-colors ${
                isActive
                  ? "border-[#FF6B00] text-[#FF6B00] bg-[#1E3349]/30"
                  : "border-transparent text-[#6B85A8] hover:text-[#E8F0FE]"
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          )
        })}
      </div>

      {/* Tab Panels */}
      <div className="flex-1">
        {activeTab === "axiom" && <PhysicsMonitor />}
        {activeTab === "brahma" && <ThreatAssessment />}
        {activeTab === "sitrep" && <SitrepPanel />}
        {activeTab === "queue" && <AuthorizationQueue />}
        {activeTab === "kali" && <KaliInsights />}
      </div>
    </div>
  )
}
