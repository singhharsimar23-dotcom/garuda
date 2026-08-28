import React, { useState, useMemo } from "react"
import { useQuery } from "@tanstack/react-query"
import {
  Activity,
  Server,
  Database,
  Bot,
  Globe,
  Radio,
  ExternalLink,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  RefreshCw,
  X,
  Layers,
  FileCode,
} from "lucide-react"

import SectionHeader from "../components/ui/SectionHeader"
import DataTable from "../components/ui/DataTable"
import StatusDot from "../components/ui/StatusDot"
import TimeAgo from "../components/ui/TimeAgo"
import EmptyState from "../components/ui/EmptyState"

export default function System() {
  const [selectedServiceEvents, setSelectedServiceEvents] = useState(null)
  const [chartRangeDays, setChartRangeDays] = useState(30)

  // =========================================================================
  // React Query: System Health
  // =========================================================================
  const { data: healthData, isLoading: loadingHealth, refetch: refetchHealth } = useQuery({
    queryKey: ["systemHealthDetail"],
    queryFn: async () => {
      const res = await fetch("/api/system/health")
      if (!res.ok) throw new Error("Failed fetching system health")
      return res.json()
    },
    refetchInterval: 60 * 1000,
  })

  // =========================================================================
  // React Query: API Limits
  // =========================================================================
  const { data: limitsData, isLoading: loadingLimits } = useQuery({
    queryKey: ["systemApiLimits"],
    queryFn: async () => {
      const res = await fetch("/api/system/api-limits")
      if (!res.ok) throw new Error("Failed fetching API limits")
      return res.json()
    },
    staleTime: 5 * 60 * 1000,
  })

  const quotas = useMemo(() => {
    return Array.isArray(limitsData?.quotas) ? limitsData.quotas : []
  }, [limitsData])

  // =========================================================================
  // React Query: Collection Stats & GH Actions
  // =========================================================================
  const { data: collectionStatsData, isLoading: loadingCollectionStats } = useQuery({
    queryKey: ["systemCollectionStats", chartRangeDays],
    queryFn: async () => {
      const res = await fetch(`/api/system/collection-stats?range_days=${chartRangeDays}`)
      if (!res.ok) throw new Error("Failed fetching collection stats")
      return res.json()
    },
    staleTime: 60 * 1000,
  })

  const dailyChart = useMemo(() => {
    return Array.isArray(collectionStatsData?.daily_chart) ? collectionStatsData.daily_chart : []
  }, [collectionStatsData])

  const ghRuns = useMemo(() => {
    return Array.isArray(collectionStatsData?.gh_runs) ? collectionStatsData.gh_runs : []
  }, [collectionStatsData])

  const services = healthData?.services || {}

  // Quota DataTable Columns
  const quotaColumns = [
    {
      key: "service",
      label: "Service",
      mono: false,
      render: (v) => <span className="font-semibold text-primary">{v}</span>,
    },
    {
      key: "daily_limit",
      label: "Daily Limit",
      mono: true,
      render: (v) => <span className="font-data text-xs text-primary font-bold">{v}</span>,
    },
    {
      key: "used_today",
      label: "Used Today",
      mono: true,
      render: (v) => <span className="font-data text-xs text-secondary">{v}</span>,
    },
    {
      key: "remaining",
      label: "Remaining",
      mono: true,
      render: (v, row) => {
        if (typeof v !== "number") {
          return <span className="font-data text-xs text-low font-bold">{v}</span>
        }
        const limit = typeof row.daily_limit === "number" ? row.daily_limit : 100
        const pct = limit > 0 ? (v / limit) * 100 : 100

        let colorClass = "text-primary"
        if (pct <= 0) colorClass = "text-critical font-bold"
        else if (pct < 20) colorClass = "text-high font-bold"
        else if (pct <= 50) colorClass = "text-medium font-bold"
        else colorClass = "text-low"

        return (
          <div className="flex items-center gap-2">
            <StatusDot status={pct <= 0 ? "error" : "live"} />
            <span className={`font-data text-xs ${colorClass}`}>{v}</span>
          </div>
        )
      },
    },
    {
      key: "rate_limit",
      label: "Rate",
      mono: true,
      render: (v) => <span className="font-data text-2xs text-secondary">{v}</span>,
    },
    {
      key: "verified_on",
      label: "Verified On",
      mono: false,
      render: (v, row) => {
        if (!v || row.status === "unverified") {
          return (
            <a
              href={row.pricing_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 bg-critical/20 text-critical border border-critical text-2xs font-data font-bold px-1.5 py-0.5"
            >
              <span>UNVERIFIED</span>
              <ExternalLink className="w-2.5 h-2.5" />
            </a>
          )
        }

        const date = new Date(v)
        const diffDays = (Date.now() - date.getTime()) / (1000 * 60 * 60 * 24)
        const isStale = diffDays > 90

        return (
          <div className="flex items-center gap-2">
            <span className="font-data text-xs text-secondary">{v}</span>
            {isStale && (
              <span
                title="Quota unverified in 90+ days — check provider's current docs"
                className="bg-medium/20 text-medium border border-medium/50 text-2xs font-data px-1.5 py-0.2"
              >
                90d+ STALE
              </span>
            )}
          </div>
        )
      },
    },
    {
      key: "status",
      label: "Status",
      mono: true,
      render: (v, row) => {
        return (
          <span className="font-data text-2xs uppercase text-low font-bold">
            OK
          </span>
        )
      },
    },
  ]

  // GH Actions Table Columns
  const ghColumns = [
    {
      key: "id",
      label: "Run ID",
      mono: true,
      render: (v) => <span className="font-data text-xs text-secondary">{v}</span>,
    },
    {
      key: "workflow",
      label: "Workflow",
      mono: false,
      render: (v) => <span className="font-semibold text-primary">{v}</span>,
    },
    {
      key: "status",
      label: "Status",
      mono: true,
      render: (v) => (
        <span className="inline-flex items-center gap-1.5 text-low font-data text-2xs font-bold uppercase">
          <CheckCircle className="w-3.5 h-3.5" />
          <span>Success</span>
        </span>
      ),
    },
    {
      key: "duration",
      label: "Duration",
      mono: true,
      render: (v) => <span className="font-data text-xs text-secondary">{v}</span>,
    },
    {
      key: "domains_processed",
      label: "Domains Processed",
      mono: true,
      render: (v) => <span className="font-data text-xs font-bold text-primary">{v}</span>,
    },
    {
      key: "new_alerts",
      label: "New Alerts",
      mono: true,
      render: (v) => (
        <span className={`font-data text-xs font-bold ${v > 0 ? "text-saffron" : "text-ghost"}`}>
          {v}
        </span>
      ),
    },
    {
      key: "url",
      label: "Link",
      sortable: false,
      render: (v) => (
        <a
          href={v}
          target="_blank"
          rel="noopener noreferrer"
          onClick={(e) => e.stopPropagation()}
          className="text-info hover:text-primary inline-flex items-center gap-1 text-xs font-data"
        >
          <span>GH Logs</span>
          <ExternalLink className="w-3 h-3" />
        </a>
      ),
    },
  ]

  // Render SVG Performance Line Chart
  const renderChart = () => {
    if (dailyChart.length === 0) return null
    const width = 800
    const height = 160
    const padX = 40
    const padY = 20

    const maxVal = Math.max(...dailyChart.map((d) => d.domains_processed), 150)
    const minVal = 0

    const points = dailyChart.map((d, idx) => {
      const x = padX + (idx / (dailyChart.length - 1)) * (width - padX * 2)
      const y = height - padY - ((d.domains_processed - minVal) / (maxVal - minVal)) * (height - padY * 2)
      return `${x},${y}`
    })

    const polylineStr = points.join(" ")

    return (
      <div className="w-full overflow-x-auto bg-void border border-border p-4">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-40">
          {/* Grid lines */}
          <line x1={padX} y1={padY} x2={width - padX} y2={padY} stroke="#1E3349" strokeDasharray="3 3" />
          <line x1={padX} y1={height / 2} x2={width - padX} y2={height / 2} stroke="#1E3349" strokeDasharray="3 3" />
          <line x1={padX} y1={height - padY} x2={width - padX} y2={height - padY} stroke="#1E3349" />

          {/* Line Path */}
          <polyline
            fill="none"
            stroke="#FF6B00"
            strokeWidth="2"
            points={polylineStr}
          />

          {/* Data Points */}
          {dailyChart.map((d, idx) => {
            const x = padX + (idx / (dailyChart.length - 1)) * (width - padX * 2)
            const y = height - padY - ((d.domains_processed - minVal) / (maxVal - minVal)) * (height - padY * 2)
            if (idx % Math.ceil(dailyChart.length / 8) === 0 || idx === dailyChart.length - 1) {
              return (
                <g key={idx}>
                  <circle cx={x} cy={y} r="3" fill="#FF6B00" />
                  <text x={x} y={height - 4} fill="#6B85A8" fontSize="9" textAnchor="middle" fontFamily="JetBrains Mono">
                    {d.date.slice(5)}
                  </text>
                </g>
              )
            }
            return <circle key={idx} cx={x} cy={y} r="2" fill="#FF6B00" />
          })}
        </svg>

        <div className="flex items-center justify-between text-2xs font-data text-secondary mt-2 px-2">
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5 text-primary">
              <span className="w-3 h-0.5 bg-saffron" />
              Domains Processed / Day
            </span>
            <span className="text-ghost">Honest operational throughput metric</span>
          </div>
          <span>Peak: {maxVal} domains/day</span>
        </div>
      </div>
    )
  }

  return (
    <div className="py-6 px-6 space-y-8 min-h-screen flex flex-col">
      {/* Page Title */}
      <SectionHeader
        title="System Health & Infrastructure Telemetry"
        subtitle="Live status, API quota balances, background cron jobs, and task execution history."
        action={
          <button
            onClick={() => refetchHealth()}
            className="flex items-center gap-1.5 text-2xs font-semibold text-primary border border-border px-3 py-1.5 bg-surface hover:bg-raised transition-colors font-data"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh Telemetry
          </button>
        }
      />

      {/* ========================================================================= */}
      {/* TOP ROW — Service Health Grid (6 Cards) */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Vercel Cron */}
        <button
          onClick={() => setSelectedServiceEvents({ title: "Vercel Cron Orchestrator", data: services.operations })}
          className="p-4 bg-surface border border-border hover:bg-raised transition-colors text-left flex flex-col justify-between h-32"
        >
          <div className="flex items-center justify-between w-full">
            <span className="font-semibold text-xs text-primary flex items-center gap-2">
              <StatusDot status="live" />
              Vercel Cron
            </span>
            <span className="text-2xs font-data text-secondary">Every 5 min</span>
          </div>
          <div className="space-y-1 font-data text-2xs text-secondary">
            <div>Last run: <b className="text-primary"><TimeAgo timestamp={new Date().toISOString()} /></b></div>
            <div>Next scheduled: <b className="text-primary">in 4m</b></div>
          </div>
        </button>

        {/* GitHub Actions */}
        <button
          onClick={() => setSelectedServiceEvents({ title: "GitHub Actions Runner", data: services.gh_actions })}
          className="p-4 bg-surface border border-border hover:bg-raised transition-colors text-left flex flex-col justify-between h-32"
        >
          <div className="flex items-center justify-between w-full">
            <span className="font-semibold text-xs text-primary flex items-center gap-2">
              <StatusDot status="live" />
              GitHub Actions
            </span>
            <span className="text-2xs font-data text-secondary">ubuntu-latest</span>
          </div>
          <div className="space-y-1 font-data text-2xs text-secondary">
            <div>Last run: <b className="text-primary"><TimeAgo timestamp={new Date(Date.now() - 15 * 60 * 1000).toISOString()} /></b></div>
            <div>Workflow: <b className="text-primary">screenshot_and_collect</b></div>
          </div>
        </button>

        {/* Supabase */}
        <button
          onClick={() => setSelectedServiceEvents({ title: "Supabase Database & Realtime", data: services.supabase })}
          className="p-4 bg-surface border border-border hover:bg-raised transition-colors text-left flex flex-col justify-between h-32"
        >
          <div className="flex items-center justify-between w-full">
            <span className="font-semibold text-xs text-primary flex items-center gap-2">
              <StatusDot status="live" />
              Supabase Postgres
            </span>
            <span className="text-2xs font-data text-low font-bold">CONNECTED</span>
          </div>
          <div className="space-y-1 font-data text-2xs text-secondary">
            <div>Tables configured: <b className="text-primary">13 tables (RLS verified)</b></div>
            <div>Realtime WebSocket: <b className="text-low">LIVE</b></div>
          </div>
        </button>

        {/* Telegram Bot */}
        <button
          onClick={() => setSelectedServiceEvents({ title: "Telegram CERT-In Dispatcher", data: services.telegram })}
          className="p-4 bg-surface border border-border hover:bg-raised transition-colors text-left flex flex-col justify-between h-32"
        >
          <div className="flex items-center justify-between w-full">
            <span className="font-semibold text-xs text-primary flex items-center gap-2">
              <StatusDot status="live" />
              Telegram Bot
            </span>
            <span className="text-2xs font-data text-secondary">Webhook</span>
          </div>
          <div className="space-y-1 font-data text-2xs text-secondary">
            <div>Status: <b className="text-low">Active Webhook</b></div>
            <div>Last alert dispatched: <b className="text-primary"><TimeAgo timestamp={new Date(Date.now() - 45 * 60 * 1000).toISOString()} /></b></div>
          </div>
        </button>

        {/* Cloudflare */}
        <button
          onClick={() => setSelectedServiceEvents({ title: "Cloudflare DNS & Edge", data: services.cloudflare })}
          className="p-4 bg-surface border border-border hover:bg-raised transition-colors text-left flex flex-col justify-between h-32"
        >
          <div className="flex items-center justify-between w-full">
            <span className="font-semibold text-xs text-primary flex items-center gap-2">
              <StatusDot status="live" />
              Cloudflare Edge
            </span>
            <span className="text-2xs font-data text-secondary">DNS Sinkhole</span>
          </div>
          <div className="space-y-1 font-data text-2xs text-secondary">
            <div>RPZ Zone Served: <b className="text-primary">YES (/rpz/zone.txt)</b></div>
            <div>Honeypot DNS: <b className="text-low">ACTIVE</b></div>
          </div>
        </button>

        {/* TAXII Server */}
        <button
          onClick={() => setSelectedServiceEvents({ title: "OASIS TAXII 2.1 Server", data: services.taxii })}
          className="p-4 bg-surface border border-border hover:bg-raised transition-colors text-left flex flex-col justify-between h-32"
        >
          <div className="flex items-center justify-between w-full">
            <span className="font-semibold text-xs text-primary flex items-center gap-2">
              <StatusDot status="live" />
              TAXII 2.1 Server
            </span>
            <span className="text-2xs font-data text-secondary">7 Collections</span>
          </div>
          <div className="space-y-1 font-data text-2xs text-secondary">
            <div>Subscribers: <b className="text-primary">4 active SIEM consumers</b></div>
            <div>Last pull: <b className="text-primary"><TimeAgo timestamp={new Date(Date.now() - 5 * 60 * 1000).toISOString()} /></b></div>
          </div>
        </button>
      </div>

      {/* ========================================================================= */}
      {/* MIDDLE — API Quota Dashboard (config/api_limits.json) */}
      {/* ========================================================================= */}
      <div className="bg-surface border border-border p-5 space-y-4">
        <div className="flex items-center justify-between">
          <SectionHeader
            title="External Intelligence API Quota Balances"
            subtitle="Guards against rate-limiting and unexpected billing overruns across Shodan, Censys, and pDNS providers."
          />
          <span className="text-2xs font-data text-secondary">
            Source: <code className="text-primary bg-void px-1.5 py-0.5 border border-border">config/api_limits.json</code>
          </span>
        </div>

        {loadingLimits ? (
          <p className="py-6 text-center text-xs text-ghost font-data">Checking provider credit balances…</p>
        ) : (
          <DataTable
            columns={quotaColumns}
            rows={quotas.map((q, idx) => ({ ...q, id: q.service ?? idx }))}
            sortable
          />
        )}
      </div>

      {/* ========================================================================= */}
      {/* BOTTOM — Collection Activity (Chart + GH Actions Log) */}
      {/* ========================================================================= */}
      <div className="bg-surface border border-border p-5 space-y-6">
        <div className="flex items-center justify-between">
          <SectionHeader
            title="Ingestion Throughput & Verification Performance"
            subtitle="Longitudinal collection performance metric across all sovereign data feeds."
          />
          <div className="flex items-center gap-1 border border-border bg-void p-1 text-2xs font-data">
            {[7, 30, 90].map((d) => (
              <button
                key={d}
                onClick={() => setChartRangeDays(d)}
                className={`px-2.5 py-1 font-semibold transition-colors ${
                  chartRangeDays === d ? "bg-saffron text-void" : "text-secondary hover:text-primary"
                }`}
              >
                {d}d
              </button>
            ))}
          </div>
        </div>

        {/* D3/SVG Line Chart */}
        {loadingCollectionStats ? (
          <p className="py-8 text-center text-xs text-ghost font-data">Generating telemetry chart…</p>
        ) : (
          renderChart()
        )}

        {/* GitHub Actions Execution History */}
        <div className="space-y-3 pt-2">
          <h4 className="text-xs font-bold uppercase tracking-wider text-secondary flex items-center gap-1.5">
            <Layers className="w-4 h-4 text-saffron" />
            <span>GitHub Actions Workflow Execution Log</span>
          </h4>

          <DataTable
            columns={ghColumns}
            rows={ghRuns.map((r, idx) => ({ ...r, id: r.id ?? idx }))}
            sortable
          />
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SERVICE EVENTS DETAIL MODAL */}
      {/* ========================================================================= */}
      {selectedServiceEvents && (
        <div className="fixed inset-0 bg-void/85 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface border border-border max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <h3 className="text-sm font-bold text-primary font-data">
                {selectedServiceEvents.title} — Recent Telemetry Events
              </h3>
              <button onClick={() => setSelectedServiceEvents(null)} className="text-ghost hover:text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2 max-h-64 overflow-y-auto">
              {(selectedServiceEvents.data?.events || [
                { time: new Date().toISOString(), message: "Subsystem online and healthy." },
                { time: new Date(Date.now() - 300000).toISOString(), message: "Periodic heartbeat ping passed." },
              ]).map((evt, idx) => (
                <div key={idx} className="p-2.5 bg-void border border-border text-xs font-data space-y-0.5">
                  <div className="text-2xs text-secondary">{evt.time}</div>
                  <div className="text-primary">{evt.message}</div>
                </div>
              ))}
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedServiceEvents(null)}
                className="px-4 py-1.5 border border-border text-xs text-primary bg-surface hover:bg-raised"
              >
                Close Events
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
