import React, { useEffect } from "react"
import { Routes, Route } from "react-router-dom"
import { Toaster, toast } from "react-hot-toast"

import Sidebar from "./components/Sidebar"
import Dashboard from "./pages/Dashboard"
import AlertDetail from "./pages/AlertDetail"
import Alerts from "./pages/Alerts"
import Campaigns from "./pages/Campaigns"
import Retrohunt from "./pages/Retrohunt"
import StixFeed from "./pages/StixFeed"
import AuditLog from "./pages/AuditLog"
import { supabase } from "./lib/supabase"
import { useGarudaStore } from "./store/useGarudaStore"

export default function App() {
  const { addAlert, setRealtimeConnected, alerts } = useGarudaStore()

  useEffect(() => {
    // Subscribe to Supabase Realtime WebSocket changes on 'alerts' table
    try {
      const channel = supabase
        .channel("garuda_alerts")
        .on(
          "postgres_changes",
          { event: "INSERT", schema: "public", table: "alerts" },
          (payload) => {
            if (payload?.new) {
              addAlert(payload.new)
              toast(
                `🚨 New Threat Ingested: ${payload.new.domain} (${payload.new.score || 70}/100)`,
                {
                  icon: "🚨",
                  style: {
                    background: "#0b132b",
                    color: "#f8fafc",
                    border: "1px solid #ef4444",
                    fontSize: "12px",
                    fontWeight: "600",
                  },
                }
              )
            }
          }
        )
        .subscribe((status) => {
          setRealtimeConnected(status === "SUBSCRIBED")
        })

      return () => {
        supabase.removeChannel(channel)
      }
    } catch (err) {
      console.warn("Realtime subscription fallback:", err)
    }
  }, [addAlert, setRealtimeConnected])

  return (
    <div className="flex h-screen bg-navy-950 text-gray-100 font-sans overflow-hidden">
      <Toaster position="top-right" />
      <Sidebar />

      {/* Main Content Area */}
      <main className="flex-1 overflow-y-auto p-6 md:p-8 bg-gradient-to-b from-navy-950 via-navy-900 to-navy-950">
        <div className="max-w-7xl mx-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/alerts/:id" element={<AlertDetail />} />
            <Route path="/campaigns" element={<Campaigns />} />
            <Route path="/retrohunt" element={<Retrohunt />} />
            <Route path="/stix" element={<StixFeed />} />
            <Route path="/audit" element={<AuditLog />} />
          </Routes>
        </div>
      </main>
    </div>
  )
}
