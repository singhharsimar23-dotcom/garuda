import React, { useEffect, useRef, useState } from "react"
import { Chart, ArcElement, Tooltip, Legend, DoughnutController } from "chart.js"
import { Activity, Clock, TrendingDown } from "lucide-react"

import SectionHeader from "../components/ui/SectionHeader"
import DataTable from "../components/ui/DataTable"
import EmptyState from "../components/ui/EmptyState"

Chart.register(ArcElement, Tooltip, Legend, DoughnutController)

const STATE_COLORS = {
  active: "#34C759",
  parked: "#FFD60A",
  dead: "#6B85A8",
  transferred: "#FF9500",
  sinkholed: "#0A84FF",
}

function burnBadgeClass(interpretation) {
  if (interpretation === "unaware") return "bg-low/20 text-low border-low/40"
  if (interpretation === "aware") return "bg-critical/20 text-critical border-critical/40"
  return "bg-high/20 text-high border-high/40"
}

function burnLabel(interpretation) {
  if (interpretation === "unaware") return "Operators likely unaware"
  if (interpretation === "aware") return "Fast burn — may detect GARUDA"
  return "Moderate burn cadence"
}

export default function LifecycleDashboard() {
  const chartRef = useRef(null)
  const chartInstance = useRef(null)
  const [summary, setSummary] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch("/api/lifecycle/summary")
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => setSummary(data))
      .catch(() => setSummary(null))
      .finally(() => setLoading(false))
  }, [])

  const stateCounts = summary?.state_counts || {}
  const states = ["active", "parked", "dead", "transferred", "sinkholed"]
  const total = states.reduce((s, k) => s + (stateCounts[k] || 0), 0)

  useEffect(() => {
    if (!chartRef.current || total === 0) return

    if (chartInstance.current) {
      chartInstance.current.destroy()
    }

    chartInstance.current = new Chart(chartRef.current, {
      type: "doughnut",
      data: {
        labels: states.map((s) => s.toUpperCase()),
        datasets: [{
          data: states.map((s) => stateCounts[s] || 0),
          backgroundColor: states.map((s) => STATE_COLORS[s]),
          borderColor: "#060B14",
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "right",
            labels: { color: "#6B85A8", font: { family: "JetBrains Mono", size: 11 } },
          },
        },
      },
    })

    return () => {
      if (chartInstance.current) {
        chartInstance.current.destroy()
        chartInstance.current = null
      }
    }
  }, [summary, total])

  const burnColumns = [
    {
      key: "cluster_label",
      label: "Cluster",
      mono: true,
      render: (v) => <span className="font-data text-primary">{v}</span>,
    },
    {
      key: "median_burn_days",
      label: "Median Burn (days)",
      mono: true,
      render: (v) => <span className="font-data font-bold">{v}</span>,
    },
    {
      key: "interpretation",
      label: "Interpretation",
      render: (v) => (
        <span className={`font-data text-2xs font-bold uppercase px-2 py-0.5 border ${burnBadgeClass(v)}`}>
          {burnLabel(v)}
        </span>
      ),
    },
  ]

  const eff = summary?.effectiveness || {}

  return (
    <div className="py-6 px-6 space-y-6 min-h-screen">
      <SectionHeader
        title="Campaign Lifecycle Tracker"
        subtitle="Post-detection IOC state monitoring — burn cadence, relocation, and GARUDA lead-time effectiveness."
      />

      {loading ? (
        <p className="text-xs text-ghost py-10 text-center">Loading lifecycle telemetry…</p>
      ) : !summary ? (
        <EmptyState
          icon={Activity}
          title="No lifecycle data"
          message="Lifecycle sweeps run daily via GitHub Actions. Confirmed IOC state transitions appear here."
        />
      ) : (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* State distribution chart */}
            <div className="lg:col-span-5 bg-surface border border-border p-4">
              <h3 className="text-2xs font-bold text-secondary uppercase tracking-widest mb-4">
                State Distribution
              </h3>
              {total === 0 ? (
                <EmptyState
                  icon={Activity}
                  title="No confirmed IOCs tracked"
                  message="Lifecycle states are recorded for confirmed alerts only."
                />
              ) : (
                <div className="h-[280px]" data-testid="lifecycle-chart">
                  <canvas ref={chartRef} />
                </div>
              )}
            </div>

            {/* Effectiveness metrics */}
            <div className="lg:col-span-7 bg-surface border border-border p-4 space-y-4">
              <h3 className="text-2xs font-bold text-secondary uppercase tracking-widest flex items-center gap-2">
                <Clock className="w-4 h-4 text-saffron" />
                Effectiveness Metrics
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-void border border-border p-4">
                  <p className="text-2xs text-secondary uppercase">Mean Lead Time</p>
                  <p className="font-data text-2xl font-bold text-primary mt-1">
                    {eff.mean_lead_time_days != null ? `${eff.mean_lead_time_days}d` : "—"}
                  </p>
                  <p className="text-2xs text-ghost mt-1">Before public disclosure</p>
                </div>
                <div className="bg-void border border-border p-4">
                  <p className="text-2xs text-secondary uppercase">Positive Lead Time Rate</p>
                  <p className="font-data text-2xl font-bold text-low mt-1">
                    {eff.positive_lead_time_rate_pct != null ? `${eff.positive_lead_time_rate_pct}%` : "—"}
                  </p>
                  <p className="text-2xs text-ghost mt-1">
                    {eff.count_positive_lead_time ?? 0} of {eff.total_with_disclosure_date ?? 0} IOCs detected first
                  </p>
                </div>
                <div className="bg-void border border-border p-4 md:col-span-2">
                  <p className="text-2xs text-secondary uppercase">Burn Rate Assessment</p>
                  <p className="font-data text-sm text-primary mt-1">
                    {(eff.burn_rate_assessment || "not_computed").replace(/_/g, " ")}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Cluster burn rate table */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold text-secondary uppercase tracking-widest flex items-center gap-2">
              <TrendingDown className="w-4 h-4 text-high" />
              Cluster Burn Rate
            </h3>
            {(summary.cluster_burn || []).length === 0 ? (
              <EmptyState
                icon={TrendingDown}
                title="Insufficient burn data"
                message="Cluster burn rates require confirmed IOCs with lifecycle_state=dead and cluster_id assigned."
              />
            ) : (
              <DataTable
                columns={burnColumns}
                rows={(summary.cluster_burn || []).map((r, i) => ({ ...r, id: r.cluster_label || i }))}
                sortable
              />
            )}
          </div>
        </>
      )}
    </div>
  )
}
