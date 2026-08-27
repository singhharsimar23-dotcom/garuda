import React, { useState } from "react"
import { Link } from "react-router-dom"
import { CheckCircle2, XCircle, Search, ShieldAlert, ArrowUpDown } from "lucide-react"

export default function AlertTable({ alerts = [], onConfirm, onReject, isLoading = false }) {
  const [filterText, setFilterText] = useState("")
  const [selectedStatus, setSelectedStatus] = useState("all")
  const [sortField, setSortField] = useState("score")
  const [sortAsc, setSortAsc] = useState(false)

  // Filter alerts
  const filtered = alerts.filter((a) => {
    const matchesText =
      !filterText ||
      a.domain?.toLowerCase().includes(filterText.toLowerCase()) ||
      a.sector?.toLowerCase().includes(filterText.toLowerCase()) ||
      a.registrar?.toLowerCase().includes(filterText.toLowerCase())

    const matchesStatus =
      selectedStatus === "all" ||
      (selectedStatus === "pending" && a.status === "pending") ||
      (selectedStatus === "confirmed" && a.status === "confirmed") ||
      (selectedStatus === "false_positive" && a.status === "false_positive")

    return matchesText && matchesStatus
  })

  // Sort alerts
  const sorted = [...filtered].sort((a, b) => {
    let valA = a[sortField] || 0
    let valB = b[sortField] || 0
    if (typeof valA === "string") valA = valA.toLowerCase()
    if (typeof valB === "string") valB = valB.toLowerCase()

    if (valA < valB) return sortAsc ? -1 : 1
    if (valA > valB) return sortAsc ? 1 : -1
    return 0
  })

  const toggleSort = (field) => {
    if (sortField === field) {
      setSortAsc(!sortAsc)
    } else {
      setSortField(field)
      setSortAsc(false)
    }
  }

  const getScoreBadge = (score) => {
    if (score >= 85) {
      return "bg-red-500/20 text-red-400 border-red-500/40"
    }
    if (score >= 70) {
      return "bg-orange-500/20 text-orange-400 border-orange-500/40"
    }
    if (score >= 40) {
      return "bg-yellow-500/20 text-yellow-400 border-yellow-500/40"
    }
    return "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
  }

  const getStatusBadge = (status) => {
    if (status === "confirmed") {
      return "bg-red-950/80 text-red-400 border-red-800"
    }
    if (status === "false_positive") {
      return "bg-gray-800 text-gray-400 border-gray-700"
    }
    return "bg-amber-950/70 text-amber-300 border-amber-800 animate-pulse"
  }

  return (
    <div className="bg-navy-900 border border-navy-700/80 rounded-xl overflow-hidden shadow-2xl">
      {/* Table Controls */}
      <div className="p-4 border-b border-navy-700/80 flex flex-col md:flex-row gap-3 justify-between items-center bg-navy-950/40">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 absolute left-3 top-3 text-gray-500" />
          <input
            type="text"
            placeholder="Search domain, sector, registrar..."
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            className="w-full bg-navy-900 border border-navy-700 rounded-lg pl-9 pr-3 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500 transition-colors"
          />
        </div>

        <div className="flex items-center space-x-2 w-full md:w-auto justify-end">
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="bg-navy-900 border border-navy-700 rounded-lg px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Statuses</option>
            <option value="pending">Pending Triage</option>
            <option value="confirmed">Confirmed Threat</option>
            <option value="false_positive">False Positive</option>
          </select>
          <span className="text-xs text-gray-400 font-mono">
            {sorted.length} {sorted.length === 1 ? "Alert" : "Alerts"}
          </span>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-gray-300">
          <thead className="bg-navy-950/80 text-[11px] uppercase tracking-wider text-gray-400 border-b border-navy-700">
            <tr>
              <th className="px-4 py-3 cursor-pointer hover:text-white" onClick={() => toggleSort("domain")}>
                <div className="flex items-center space-x-1">
                  <span>Target Threat Domain</span>
                  <ArrowUpDown className="w-3 h-3 opacity-60" />
                </div>
              </th>
              <th className="px-4 py-3 cursor-pointer hover:text-white" onClick={() => toggleSort("score")}>
                <div className="flex items-center space-x-1">
                  <span>Score</span>
                  <ArrowUpDown className="w-3 h-3 opacity-60" />
                </div>
              </th>
              <th className="px-4 py-3">Target Sector</th>
              <th className="px-4 py-3">Registrar / Host</th>
              <th className="px-4 py-3 cursor-pointer hover:text-white" onClick={() => toggleSort("age_days")}>
                <div className="flex items-center space-x-1">
                  <span>Age</span>
                  <ArrowUpDown className="w-3 h-3 opacity-60" />
                </div>
              </th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3 text-right">SOC Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-navy-800">
            {isLoading ? (
              <tr>
                <td colSpan="7" className="px-4 py-8 text-center text-gray-500">
                  <div className="flex justify-center items-center space-x-2">
                    <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                    <span>Streaming threat telemetry...</span>
                  </div>
                </td>
              </tr>
            ) : sorted.length === 0 ? (
              <tr>
                <td colSpan="7" className="px-4 py-8 text-center text-gray-500 italic">
                  No threat indicators matching query filters.
                </td>
              </tr>
            ) : (
              sorted.map((alert) => (
                <tr key={alert.id} className="hover:bg-navy-800/50 transition-colors">
                  {/* Domain */}
                  <td className="px-4 py-3 font-mono font-bold text-gray-100">
                    <Link to={`/alerts/${alert.id}`} className="text-cyan-400 hover:underline flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                      {alert.domain}
                    </Link>
                  </td>

                  {/* Score */}
                  <td className="px-4 py-3">
                    <span className={`px-2.5 py-1 rounded-md border font-mono font-bold text-xs ${getScoreBadge(alert.score)}`}>
                      {alert.score}/100
                    </span>
                  </td>

                  {/* Sector */}
                  <td className="px-4 py-3 text-gray-300">
                    {alert.sector || "National Defence"}
                  </td>

                  {/* Registrar */}
                  <td className="px-4 py-3 text-gray-400 text-[11px]">
                    <div>{alert.registrar || "Unknown"}</div>
                    {alert.hosting_asn && <div className="font-mono text-gray-500">AS{alert.hosting_asn}</div>}
                  </td>

                  {/* Age */}
                  <td className="px-4 py-3 font-mono text-gray-300">
                    {alert.age_days !== undefined && alert.age_days !== null ? `${alert.age_days}d` : "New"}
                  </td>

                  {/* Status */}
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${getStatusBadge(alert.status)}`}>
                      {alert.status}
                    </span>
                  </td>

                  {/* Actions */}
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end space-x-1.5">
                      {alert.status !== "confirmed" && (
                        <button
                          onClick={() => onConfirm && onConfirm(alert)}
                          className="px-2 py-1 rounded bg-red-600/80 hover:bg-red-600 text-white font-semibold text-[10px] flex items-center space-x-1 transition-all"
                          title="Confirm as Malicious Infrastructure"
                        >
                          <CheckCircle2 className="w-3 h-3" />
                          <span>Confirm</span>
                        </button>
                      )}
                      {alert.status !== "false_positive" && (
                        <button
                          onClick={() => onReject && onReject(alert)}
                          className="px-2 py-1 rounded bg-gray-700 hover:bg-gray-600 text-gray-200 font-semibold text-[10px] flex items-center space-x-1 transition-all"
                          title="Reject as False Positive"
                        >
                          <XCircle className="w-3 h-3" />
                          <span>Reject</span>
                        </button>
                      )}
                      <Link
                        to={`/alerts/${alert.id}`}
                        className="px-2 py-1 rounded bg-navy-700 hover:bg-navy-600 text-cyan-300 font-semibold text-[10px] transition-all"
                      >
                        Inspect
                      </Link>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
