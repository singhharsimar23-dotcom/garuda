import React, { useEffect } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "react-hot-toast"
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Percent,
  RefreshCw,
  Zap,
} from "lucide-react"

import StatCard from "../components/StatCard"
import ThreatMap from "../components/ThreatMap"
import AlertTable from "../components/AlertTable"
import { getAlerts, getStats, confirmAlert, rejectAlert, triggerCollection } from "../lib/api"
import { useGarudaStore } from "../store/useGarudaStore"

export default function Dashboard() {
  const queryClient = useQueryClient()
  const { alerts, setAlerts, stats, setStats, updateAlert } = useGarudaStore()

  // Query: Stats
  const { data: statsData, isLoading: statsLoading } = useQuery({
    queryKey: ["stats"],
    queryFn: getStats,
    refetchInterval: 30000,
  })

  // Query: Alerts
  const { data: alertsData, isLoading: alertsLoading, refetch: refetchAlerts } = useQuery({
    queryKey: ["alerts"],
    queryFn: () => getAlerts({ limit: 50 }),
    refetchInterval: 20000,
  })

  useEffect(() => {
    if (statsData) setStats(statsData)
  }, [statsData, setStats])

  useEffect(() => {
    if (alertsData?.alerts) setAlerts(alertsData.alerts)
  }, [alertsData, setAlerts])

  // Mutation: Confirm Alert
  const confirmMutation = useMutation({
    mutationFn: (alert) =>
      confirmAlert({
        alert_id: alert.id,
        analyst_id: "dashboard_soc_analyst",
        justification: "Confirmed malicious threat infrastructure staging impersonation attack.",
      }),
    onSuccess: (data, variables) => {
      updateAlert(variables.id, { status: "confirmed" })
      toast.success(`Alert confirmed! CERT-In advisory & STIX bundle generated for ${variables.domain}`)
      queryClient.invalidateQueries({ queryKey: ["stats"] })
      queryClient.invalidateQueries({ queryKey: ["alerts"] })
    },
    onError: (err) => {
      toast.error(`Confirmation failed: ${err.message}`)
    },
  })

  // Mutation: Reject Alert
  const rejectMutation = useMutation({
    mutationFn: (alert) =>
      rejectAlert({
        alert_id: alert.id,
        analyst_id: "dashboard_soc_analyst",
        justification: "Benign authorized organization / false positive.",
        reason_code: "known_whitelist",
      }),
    onSuccess: (data, variables) => {
      updateAlert(variables.id, { status: "false_positive" })
      toast.success(`Alert marked as false positive: ${variables.domain}`)
      queryClient.invalidateQueries({ queryKey: ["stats"] })
      queryClient.invalidateQueries({ queryKey: ["alerts"] })
    },
    onError: (err) => {
      toast.error(`Rejection failed: ${err.message}`)
    },
  })

  // Mutation: Trigger Collection
  const collectMutation = useMutation({
    mutationFn: triggerCollection,
    onSuccess: () => {
      toast.success("Live intelligence feeds ingested successfully!")
      queryClient.invalidateQueries({ queryKey: ["stats"] })
      queryClient.invalidateQueries({ queryKey: ["alerts"] })
      queryClient.invalidateQueries({ queryKey: ["campaigns"] })
      setTimeout(() => {
        refetchAlerts()
      }, 1200)
    },
    onError: (err) => {
      toast.error(`Ingestion error: ${err.message}`)
    },
  })

  const currentAlerts = alerts.length > 0 ? alerts : alertsData?.alerts || []

  return (
    <div className="space-y-6 pb-10">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-navy-900/60 border border-navy-800 p-5 rounded-2xl shadow-xl">
        <div>
          <h2 className="text-xl font-black tracking-tight text-white flex items-center gap-2">
            <span>Operational Threat Overview</span>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-blue-500/20 text-blue-400 border border-blue-500/30">
              Live SOC Telemetry
            </span>
          </h2>
          <p className="text-xs text-gray-400 mt-1">
            Real-time proactive CTI monitoring for Indian Critical National Infrastructure & Defence
          </p>
        </div>

        <button
          onClick={() => collectMutation.mutate()}
          disabled={collectMutation.isPending}
          className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs flex items-center space-x-2 transition-all shadow-lg shadow-blue-600/30 disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${collectMutation.isPending ? "animate-spin" : ""}`} />
          <span>{collectMutation.isPending ? "Ingesting Feeds..." : "Poll Feeds Now"}</span>
        </button>
      </div>

      {/* 4 Stat Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Threat Alerts (24h)"
          value={stats.total_alerts_24h || 0}
          subtitle="Processed through 11-step pipeline"
          icon={ShieldAlert}
          color="blue"
        />
        <StatCard
          title="Critical Threats (Score ≥85)"
          value={stats.critical_24h || 0}
          subtitle="Direct APT36 infrastructure matches"
          icon={AlertTriangle}
          color="red"
          pulse={stats.critical_24h > 0}
        />
        <StatCard
          title="Analyst Confirmed (24h)"
          value={stats.confirmed_24h || 0}
          subtitle="Advisories & Blocklists Pushed"
          icon={CheckCircle2}
          color="orange"
        />
        <StatCard
          title="False Positive Rate (7d)"
          value={`${((stats.false_positive_rate_7d || 0) * 100).toFixed(1)}%`}
          subtitle="Active feedback learning target <5%"
          icon={Percent}
          color="emerald"
        />
      </div>

      {/* Interactive Threat Map */}
      <div className="bg-navy-900/40 border border-navy-800 p-4 rounded-2xl shadow-xl space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-gray-200 uppercase tracking-wider flex items-center gap-2">
            <Zap className="w-4 h-4 text-cyan-400" />
            <span>Active Infrastructure Geolocation & Threat Distribution</span>
          </h3>
          <span className="text-xs text-gray-400 font-mono">
            {currentAlerts.filter((a) => a.hosting_ip).length} Mapped Hosts
          </span>
        </div>
        <ThreatMap alerts={currentAlerts} />
      </div>

      {/* Recent Alerts Table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-gray-200 uppercase tracking-wider">
            Prioritized Threat Alert Stream
          </h3>
          <button
            onClick={() => refetchAlerts()}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold"
          >
            Refresh Stream
          </button>
        </div>
        <AlertTable
          alerts={currentAlerts}
          onConfirm={(alert) => confirmMutation.mutate(alert)}
          onReject={(alert) => rejectMutation.mutate(alert)}
          isLoading={alertsLoading}
        />
      </div>
    </div>
  )
}
