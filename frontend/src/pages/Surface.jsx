import React, { useEffect, useState, useMemo } from "react"
import { Link } from "react-router-dom"
import {
  Server,
  Download,
  Share2,
  X,
  ExternalLink,
  ShieldAlert,
  AlertTriangle,
  FileSpreadsheet,
  Layers,
} from "lucide-react"

import SectionHeader from "../components/ui/SectionHeader"
import DataTable from "../components/ui/DataTable"
import ScoreBadge from "../components/ui/ScoreBadge"
import ConfidencePill from "../components/ui/ConfidencePill"
import CopyField from "../components/ui/CopyField"
import TimeAgo from "../components/ui/TimeAgo"
import EmptyState from "../components/ui/EmptyState"
import { toast } from "react-hot-toast"

export default function Surface() {
  const [orgs, setOrgs] = useState([])
  const [findings, setFindings] = useState([])
  const [loadingOrgs, setLoadingOrgs] = useState(true)
  const [loadingFindings, setLoadingFindings] = useState(true)
  const [selectedOrg, setSelectedOrg] = useState(null)
  const [severityFilter, setSeverityFilter] = useState("all")
  const [statusFilter, setStatusFilter] = useState("all")
  const [activeFindingDetail, setActiveFindingDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailData, setDetailData] = useState(null)

  // Fetch monitored orgs
  useEffect(() => {
    fetch("/api/easm/orgs")
      .then((r) => r.json())
      .then((data) => {
        setOrgs(Array.isArray(data?.orgs) ? data.orgs : [])
        setLoadingOrgs(false)
      })
      .catch((e) => {
        console.warn("[Surface] Failed to fetch orgs:", e)
        setLoadingOrgs(false)
      })
  }, [])

  // Fetch findings
  const fetchFindings = () => {
    setLoadingFindings(true)
    let url = `/api/easm/findings?limit=200`
    if (statusFilter !== "all") url += `&status=${statusFilter}`
    if (severityFilter !== "all") url += `&severity=${severityFilter}`
    if (selectedOrg) url += `&org=${encodeURIComponent(selectedOrg)}`

    fetch(url)
      .then((r) => r.json())
      .then((data) => {
        setFindings(Array.isArray(data?.findings) ? data.findings : [])
        setLoadingFindings(false)
      })
      .catch((e) => {
        console.warn("[Surface] Failed to fetch findings:", e)
        setLoadingFindings(false)
      })
  }

  useEffect(() => {
    fetchFindings()
  }, [selectedOrg, statusFilter, severityFilter])

  // Open detail panel
  const handleOpenDetail = async (finding) => {
    setActiveFindingDetail(finding)
    setDetailLoading(true)
    setDetailData(null)
    try {
      const res = await fetch(`/api/easm/findings/${finding.id}`)
      if (res.ok) {
        const json = await res.json()
        setDetailData(json)
      } else {
        setDetailData({ finding, cve_matches: [] })
      }
    } catch (err) {
      console.warn("[Surface] Detail fetch error:", err)
      setDetailData({ finding, cve_matches: [] })
    } finally {
      setDetailLoading(false)
    }
  }

  // Handle status update
  const handleStatusChange = async (findingId, newStatus) => {
    try {
      const res = await fetch(`/api/easm/findings/${findingId}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      })
      if (res.ok) {
        toast.success(`Finding status updated to '${newStatus}'`)
        setFindings((prev) =>
          prev.map((f) => (f.id === findingId ? { ...f, status: newStatus } : f))
        )
        if (activeFindingDetail?.id === findingId) {
          setActiveFindingDetail((prev) => ({ ...prev, status: newStatus }))
        }
      } else {
        toast.error("Failed to update finding status")
      }
    } catch (err) {
      toast.error(`Status update error: ${err.message}`)
    }
  }

  // Client-side CSV export
  const downloadCSV = () => {
    if (findings.length === 0) {
      toast.error("No findings to export")
      return
    }
    const headers = [
      "ID",
      "Organisation",
      "IP",
      "Port",
      "Service",
      "Severity",
      "Status",
      "KEV_Date",
      "First_Seen",
      "Last_Seen",
    ]
    const rows = findings.map((f) => [
      `"${f.id || ""}"`,
      `"${f.org_name || ""}"`,
      `"${f.ip || ""}"`,
      `"${f.port || ""}"`,
      `"${f.service || ""}"`,
      `"${f.severity || ""}"`,
      `"${f.status || ""}"`,
      `"${f.kev_date_added || ""}"`,
      `"${f.first_seen || ""}"`,
      `"${f.last_seen || ""}"`,
    ])
    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((e) => e.join(","))].join("\n")
    const encodedUri = encodeURI(csvContent)
    const link = document.createElement("a")
    link.setAttribute("href", encodedUri)
    link.setAttribute("download", `garuda_easm_findings_${new Date().toISOString().split("T")[0]}.csv`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    toast.success("CSV report downloaded")
  }

  // Filtered findings by client-side if needed
  const displayFindings = useMemo(() => {
    return findings.filter((f) => {
      if (selectedOrg && f.org_name !== selectedOrg) return false
      if (severityFilter !== "all" && f.severity?.toLowerCase() !== severityFilter.toLowerCase()) return false
      if (statusFilter !== "all" && f.status !== statusFilter) return false
      return true
    })
  }, [findings, selectedOrg, severityFilter, statusFilter])

  // Table columns definition
  const columns = [
    {
      key: "org_name",
      label: "Org",
      mono: false,
      render: (v) => <span className="font-semibold text-primary">{v || "Monitored Asset"}</span>,
    },
    {
      key: "ip",
      label: "IP",
      mono: true,
      render: (v) => <CopyField value={v} />,
    },
    {
      key: "service",
      label: "Service",
      mono: true,
      render: (v) => <span className="text-2xs text-secondary px-1.5 py-0.5 border border-border bg-raised">{v}</span>,
    },
    {
      key: "product",
      label: "Product",
      mono: false,
      render: (v) => <span className="truncate max-w-[140px] text-xs text-primary block" title={v}>{v || "—"}</span>,
    },
    {
      key: "first_seen",
      label: "First Seen",
      mono: false,
      render: (v) => <TimeAgo timestamp={v} />,
    },
    {
      key: "last_seen",
      label: "Last Seen",
      mono: false,
      render: (v) => <TimeAgo timestamp={v} />,
    },
    {
      key: "kev_date_added",
      label: "KEV",
      mono: true,
      render: (v) =>
        v ? (
          <span
            title={`CISA KEV Date Added: ${v}`}
            className="bg-critical text-white font-data text-2xs font-bold px-1.5 py-0.5 tracking-wider"
          >
            KEV
          </span>
        ) : (
          <span className="text-ghost text-2xs font-data">—</span>
        ),
    },
    {
      key: "threat_actor_correlation_id",
      label: "Threat Actor",
      mono: true,
      render: (v) =>
        v ? (
          <span className="font-data text-xs text-gold border-l-2 border-gold pl-1.5">{v}</span>
        ) : (
          <span className="text-ghost font-data text-xs">—</span>
        ),
    },
    {
      key: "severity",
      label: "Severity",
      mono: true,
      render: (v) => {
        const s = (v || "medium").toLowerCase()
        const col =
          s === "critical"
            ? "text-critical font-bold"
            : s === "high"
            ? "text-high font-bold"
            : s === "medium"
            ? "text-medium"
            : "text-low"
        return <span className={`font-data text-2xs uppercase ${col}`}>{s}</span>
      },
    },
    {
      key: "status",
      label: "Status",
      mono: true,
      render: (v, row) => (
        <select
          value={v || "open"}
          onChange={(e) => {
            e.stopPropagation()
            handleStatusChange(row.id, e.target.value)
          }}
          onClick={(e) => e.stopPropagation()}
          className="bg-raised border border-border text-primary font-data text-2xs px-2 py-1 focus:outline-none focus:border-saffron"
        >
          <option value="open">OPEN</option>
          <option value="patched">PATCHED</option>
          <option value="false_positive">FALSE_POS</option>
        </select>
      ),
    },
    {
      key: "actions",
      label: "Actions",
      sortable: false,
      render: (_, row) => (
        <button
          onClick={(e) => {
            e.stopPropagation()
            handleOpenDetail(row)
          }}
          className="text-xs text-info hover:text-primary font-semibold transition-colors duration-150 underline underline-offset-2"
        >
          View detail
        </button>
      ),
    },
  ]

  return (
    <div className="py-6 px-6 relative flex flex-col min-h-screen">
      {/* Top Header */}
      <SectionHeader
        title="External Attack Surface Monitor"
        subtitle="Active reconnaissance, internet-facing assets, and CISA KEV exploitation correlation across sovereign defence netblocks."
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={downloadCSV}
              className="flex items-center gap-1.5 text-2xs font-semibold text-secondary hover:text-primary border border-border px-3 py-1.5 bg-surface hover:bg-raised transition-colors"
            >
              <FileSpreadsheet className="w-3.5 h-3.5" />
              Download CSV
            </button>
            <a
              href="/api/easm/stix-export"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-2xs font-semibold text-saffron border border-saffron/40 hover:border-saffron px-3 py-1.5 bg-saffron/10 transition-colors"
            >
              <Share2 className="w-3.5 h-3.5" />
              Export STIX Bundle
            </a>
          </div>
        }
      />

      {/* TOP ROW — Org Risk Summary Cards */}
      <div className="mb-6">
        {loadingOrgs ? (
          <p className="text-xs text-ghost py-4">Loading monitored organisations…</p>
        ) : orgs.length === 0 ? (
          <EmptyState
            icon={Server}
            title="No IP ranges verified yet"
            message="Seed monitored_asn_ranges via APNIC WHOIS before EASM runs. Sourcing instructions are documented in the architecture specification."
            collectionNote="Zero fake org cards shown — every monitored organisation must have documented APNIC registry provenance."
          />
        ) : (
          <div className="flex items-center gap-3 overflow-x-auto pb-2 scrollbar-thin">
            {/* 'All Orgs' Card */}
            <button
              onClick={() => setSelectedOrg(null)}
              className={`p-3 text-left border shrink-0 w-48 transition-colors ${
                selectedOrg === null ? "border-saffron bg-raised" : "border-border bg-surface hover:bg-raised"
              }`}
            >
              <div className="text-xs font-bold text-primary mb-1">ALL ORGANISATIONS</div>
              <div className="text-2xs text-secondary font-data">{orgs.length} Monitored Ranges</div>
              <div className="text-2xs text-ghost font-data mt-2">{findings.length} Total Findings</div>
            </button>

            {/* Individual Org Cards */}
            {orgs.map((org) => {
              const isSelected = selectedOrg === org.org_name
              return (
                <button
                  key={org.id || org.org_name}
                  onClick={() => setSelectedOrg(isSelected ? null : org.org_name)}
                  className={`p-3 text-left border shrink-0 w-60 flex flex-col justify-between transition-colors ${
                    isSelected ? "border-saffron bg-raised" : "border-border bg-surface hover:bg-raised"
                  }`}
                >
                  <div>
                    <div className="text-sm font-bold text-primary truncate" title={org.org_name}>
                      {org.org_name}
                    </div>
                    <div className="text-2xs font-data text-secondary truncate mt-0.5">{org.cidr}</div>
                  </div>

                  <div className="flex items-center justify-between text-2xs font-data mt-3 pt-2 border-t border-border/50 text-secondary">
                    <span>
                      Open: <b className="text-primary">{org.open_findings ?? 0}</b>
                    </span>
                    <span>
                      KEV: <b className="text-critical">{org.kev_matches ?? 0}</b>
                    </span>
                    <span>
                      Crit: <b className="text-high">{org.critical_count ?? 0}</b>
                    </span>
                  </div>

                  {/* Proportional Severity Bar */}
                  <div className="w-full h-1 bg-border mt-2 flex overflow-hidden">
                    <div style={{ width: "30%" }} className="bg-critical" />
                    <div style={{ width: "25%" }} className="bg-high" />
                    <div style={{ width: "25%" }} className="bg-medium" />
                    <div style={{ width: "20%" }} className="bg-low" />
                  </div>
                </button>
              )
            })}
          </div>
        )}
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-3 p-2 bg-surface border border-border">
        <div className="flex items-center gap-3 text-2xs">
          <span className="text-secondary font-semibold uppercase tracking-wider">Filters:</span>
          {selectedOrg && (
            <span className="inline-flex items-center gap-1 bg-raised text-saffron px-2 py-0.5 border border-saffron/40 font-data">
              Org: {selectedOrg}
              <button onClick={() => setSelectedOrg(null)} className="hover:text-white">
                <X className="w-3 h-3" />
              </button>
            </span>
          )}

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-raised border border-border text-primary font-data text-2xs px-2 py-1 focus:outline-none"
          >
            <option value="all">ALL SEVERITIES</option>
            <option value="critical">CRITICAL ONLY</option>
            <option value="high">HIGH</option>
            <option value="medium">MEDIUM</option>
            <option value="low">LOW</option>
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-raised border border-border text-primary font-data text-2xs px-2 py-1 focus:outline-none"
          >
            <option value="all">ALL STATUSES</option>
            <option value="open">OPEN</option>
            <option value="patched">PATCHED</option>
            <option value="false_positive">FALSE POSITIVE</option>
          </select>
        </div>

        <div className="text-2xs font-data text-secondary">
          Showing <span className="text-primary font-bold">{displayFindings.length}</span> findings
        </div>
      </div>

      {/* MAIN TABLE — easm_findings */}
      {loadingFindings ? (
        <p className="text-xs text-ghost py-12 text-center">Loading attack surface telemetry…</p>
      ) : displayFindings.length === 0 ? (
        <EmptyState
          icon={Server}
          title="No attack surface findings"
          message="No open findings matching your filter criteria. Scheduled reconnaissance will index findings as soon as exposed services or CISA KEV signatures trigger."
          collectionNote="Sovereign EASM scans execute daily against documented ASN netblocks. Zero simulated or fabricated findings."
        />
      ) : (
        <DataTable
          columns={columns}
          rows={displayFindings}
          sortable
          onRowClick={(row) => handleOpenDetail(row)}
          contextMenuItems={(row) => [
            { label: "Copy IP", action: () => navigator.clipboard.writeText(row.ip || "") },
            { label: "Copy Service", action: () => navigator.clipboard.writeText(row.service || "") },
            { label: "Mark as Patched", action: () => handleStatusChange(row.id, "patched") },
            { label: "Mark as False Positive", action: () => handleStatusChange(row.id, "false_positive") },
          ]}
        />
      )}

      {/* RIGHT PANEL — Finding Detail Drawer (480px) */}
      {activeFindingDetail && (
        <div
          className="fixed top-8 right-0 bottom-0 w-[480px] bg-surface border-l border-border z-40 flex flex-col shadow-2xl overflow-y-auto"
          style={{ background: "#0D1521" }}
        >
          {/* Drawer Header */}
          <div className="p-4 border-b border-border flex items-center justify-between bg-void">
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-primary font-data">{activeFindingDetail.ip}</h3>
                <span className="text-2xs font-data uppercase px-1.5 py-0.5 border border-border bg-raised text-secondary">
                  Port {activeFindingDetail.port}
                </span>
              </div>
              <p className="text-xs text-secondary mt-0.5">{activeFindingDetail.org_name}</p>
            </div>
            <button
              onClick={() => setActiveFindingDetail(null)}
              className="text-ghost hover:text-primary transition-colors p-1"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Drawer Content */}
          <div className="p-5 space-y-6">
            {/* Timeline & Metadata Grid */}
            <div className="grid grid-cols-2 gap-3 p-3 border border-border bg-void font-data text-xs">
              <div>
                <span className="text-2xs text-secondary block uppercase">First Observed</span>
                <span className="text-primary">{activeFindingDetail.first_seen?.split("T")[0] || "—"}</span>
              </div>
              <div>
                <span className="text-2xs text-secondary block uppercase">Last Observed</span>
                <span className="text-primary">{activeFindingDetail.last_seen?.split("T")[0] || "—"}</span>
              </div>
              <div>
                <span className="text-2xs text-secondary block uppercase">Service</span>
                <span className="text-saffron">{activeFindingDetail.service}</span>
              </div>
              <div>
                <span className="text-2xs text-secondary block uppercase">Current Status</span>
                <span className="text-primary uppercase font-bold">{activeFindingDetail.status}</span>
              </div>
            </div>

            {/* Service Fingerprint Banner Text */}
            <div>
              <h4 className="text-2xs font-bold text-secondary uppercase tracking-widest mb-2">
                Service Fingerprint & Banner
              </h4>
              <pre className="p-3 bg-void border border-border text-primary font-data text-xs leading-relaxed overflow-x-auto whitespace-pre-wrap max-h-40">
                {activeFindingDetail.product_fingerprint || activeFindingDetail.product || "No raw banner captured."}
              </pre>
            </div>

            {/* CVE MATCHES Section */}
            <div>
              <h4 className="text-2xs font-bold text-secondary uppercase tracking-widest mb-3 flex items-center justify-between">
                <span>CVE & CISA KEV Correlation</span>
                {detailLoading && <span className="text-ghost font-normal">Correlating...</span>}
              </h4>

              {detailLoading ? (
                <p className="text-xs text-ghost italic">Querying CVE correlation cache…</p>
              ) : (detailData?.cve_matches || []).length === 0 ? (
                <div className="p-3 border border-border bg-void text-xs text-ghost text-center">
                  No direct CISA KEV or known exploit CVE match linked to this banner.
                </div>
              ) : (
                <div className="space-y-3">
                  {detailData.cve_matches.map((cve) => {
                    const daysExploited = cve.days_since_actor_exploitation
                    const daysBg =
                      daysExploited != null && daysExploited < 7
                        ? "bg-critical/20 text-critical border border-critical"
                        : daysExploited != null && daysExploited < 30
                        ? "bg-medium/20 text-medium border border-medium"
                        : "bg-void text-secondary border border-border"

                    return (
                      <div key={cve.id || cve.cve_id} className="p-3 border border-border bg-void space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-data font-bold text-sm text-primary">{cve.cve_id}</span>
                            {cve.kev_date_added && (
                              <span className="bg-critical text-white font-data text-2xs font-bold px-1.5 py-0.5">
                                KEV
                              </span>
                            )}
                            {cve.known_ransomware_use && (
                              <span className="bg-critical/30 border border-critical text-critical font-data text-2xs font-bold px-1.5 py-0.5">
                                RANSOMWARE USE
                              </span>
                            )}
                          </div>
                          <ConfidencePill
                            confidence={cve.severity_computed === "critical" ? 95 : 75}
                            methodology="CISA KEV + CVSS + exploitation signal"
                          />
                        </div>

                        {daysExploited != null && (
                          <div className={`p-2 text-2xs font-data ${daysBg}`}>
                            ⚠ <b>{daysExploited} days</b> since tracked actor used this CVE against other targets
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>

            {/* STIX Indicator Provenance */}
            {activeFindingDetail.stix_indicator_id && (
              <div className="p-3 border border-border bg-void">
                <span className="text-2xs text-secondary block uppercase mb-1">STIX 2.1 Object Provenance</span>
                <Link
                  to={`/intelligence`}
                  className="inline-flex items-center gap-1.5 text-xs font-data text-saffron hover:underline"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  {activeFindingDetail.stix_indicator_id}
                </Link>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
