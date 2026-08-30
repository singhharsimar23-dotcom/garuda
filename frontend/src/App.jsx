import React, { useEffect } from "react"
import { Routes, Route, Navigate } from "react-router-dom"
import { Toaster, toast } from "react-hot-toast"

import StatusBar from "./components/StatusBar"
import Sidebar from "./components/Sidebar"
import GlobalSearch from "./components/GlobalSearch"

// Existing pages
import Dashboard from "./pages/Dashboard"
import AlertDetail from "./pages/AlertDetail"
import Alerts from "./pages/Alerts"
import Campaigns from "./pages/Campaigns"
import Retrohunt from "./pages/Retrohunt"
import StixFeed from "./pages/StixFeed"
import AuditLog from "./pages/AuditLog"

// New pages
import Intelligence from "./pages/Intelligence"
import Surface from "./pages/Surface"
import Network from "./pages/Network"
import Attribution from "./pages/Attribution"
import AttributionDashboard from "./pages/AttributionDashboard"
import OrbTracker from "./pages/OrbTracker"
import MalwareHunt from "./pages/MalwareHunt"
import PredictiveDashboard from "./pages/PredictiveDashboard"
import LifecycleDashboard from "./pages/LifecycleDashboard"
import System from "./pages/System"
import Phase3Dashboard from "./pages/Phase3Dashboard"

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
                `New Threat: ${payload.new.domain} (${payload.new.score || 70}/100)`,
                {
                  style: {
                    background: "#0D1521",
                    color: "#E8F0FE",
                    border: "1px solid #FF3B30",
                    fontSize: "12px",
                    fontFamily: "'JetBrains Mono', monospace",
                    borderRadius: 0,
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
    <div className="flex flex-col h-screen overflow-hidden" style={{ background: "#060B14" }}>
      <Toaster position="top-right" />
      <GlobalSearch />

      {/* Fixed 32px status bar */}
      <StatusBar />


      {/* Body below status bar */}
      <div className="flex flex-1 overflow-hidden pt-8">
        <Sidebar />

        {/* Main content */}
        <main className="flex-1 overflow-y-auto" style={{ background: "#060B14" }}>
          <Routes>
            {/* Operations section — existing pages */}
            <Route path="/"            element={<Navigate to="/operations" replace />} />
            <Route path="/operations"  element={<Dashboard />} />
            <Route path="/alerts"      element={<Alerts />} />
            <Route path="/alerts/:id"  element={<AlertDetail />} />
            <Route path="/campaigns"   element={<Campaigns />} />
            <Route path="/retrohunt"   element={<Retrohunt />} />
            <Route path="/audit"       element={<AuditLog />} />

            {/* New sections */}
            <Route path="/intelligence" element={<Intelligence />} />
            <Route path="/surface"      element={<Surface />} />
            <Route path="/network"      element={<Network />} />
            <Route path="/orb"          element={<OrbTracker />} />
            <Route path="/malware"      element={<MalwareHunt />} />
            <Route path="/attribution"  element={<AttributionDashboard />} />
            <Route path="/attribution/review" element={<Attribution />} />
            <Route path="/predictive"   element={<PredictiveDashboard />} />
            <Route path="/lifecycle"    element={<LifecycleDashboard />} />
            <Route path="/system"       element={<System />} />
            <Route path="/phase3"       element={<Phase3Dashboard />} />
            <Route path="/axiom"        element={<Phase3Dashboard />} />
            <Route path="/brahma"       element={<Phase3Dashboard />} />
            <Route path="/sitrep"       element={<Phase3Dashboard />} />
            <Route path="/queue"        element={<Phase3Dashboard />} />

            {/* Legacy redirect */}
            <Route path="/stix" element={<Navigate to="/intelligence" replace />} />

            {/* Catch-all */}
            <Route path="*" element={<Navigate to="/operations" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}
