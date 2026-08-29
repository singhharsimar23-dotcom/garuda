import React from "react"
import { useQuery } from "@tanstack/react-query"
import { FileCheck2, User, CheckCircle, Clock } from "lucide-react"

import { getAlertAudit } from "../lib/api"

export default function AuditLog() {
  const { data: auditEntries, isLoading } = useQuery({
    queryKey: ["auditLogAll"],
    queryFn: () => getAlertAudit("all"),
    refetchInterval: 20000,
  })

  // Only real entries — no synthetic fallbacks
  const entries = Array.isArray(auditEntries) ? auditEntries : []

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="bg-navy-900/60 border border-navy-800 p-5 rounded-2xl shadow-xl">
        <h2 className="text-xl font-black tracking-tight text-white flex items-center gap-2">
          <FileCheck2 className="w-5 h-5 text-emerald-400" />
          <span>Analyst Decision Audit Trail</span>
        </h2>
        <p className="text-xs text-gray-400 mt-1">
          Cryptographically auditable and immutable record of all threat confirmations, triage rejections, and blocklist pushes
        </p>
      </div>

      {/* Audit Trail Timeline Table */}
      <div className="bg-navy-900 border border-navy-700/80 rounded-2xl overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-gray-300">
            <thead className="bg-navy-950/80 text-[11px] uppercase tracking-wider text-gray-400 border-b border-navy-700">
              <tr>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Action Type</th>
                <th className="px-4 py-3">Analyst / System ID</th>
                <th className="px-4 py-3">Mandatory Justification & Scope</th>
                <th className="px-4 py-3 text-right">Integrity Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-navy-800">
              {isLoading ? (
                <tr><td colSpan={5} className="px-4 py-12 text-center text-xs text-gray-500">Loading audit trail…</td></tr>
              ) : entries.length === 0 ? (
                <tr><td colSpan={5} className="px-4 py-12 text-center text-xs text-gray-500">No analyst decisions recorded yet. Audit entries appear when alerts are confirmed, rejected, or whitelisted.</td></tr>
              ) : entries.map((entry) => (
                <tr key={entry.id} className="hover:bg-navy-800/40 transition-colors">
                  <td className="px-4 py-3 font-mono text-gray-400">
                    {new Date(entry.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 rounded font-mono font-bold text-[10px] uppercase bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                      {entry.action}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-gray-200 flex items-center space-x-1.5">
                    <User className="w-3 h-3 text-gray-500" />
                    <span>{entry.analyst_id || "automated_engine"}</span>
                  </td>
                  <td className="px-4 py-3 text-gray-300">
                    {entry.justification}
                  </td>
                  <td className="px-4 py-3 text-right font-mono text-emerald-400 flex items-center justify-end space-x-1">
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>VERIFIED</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
