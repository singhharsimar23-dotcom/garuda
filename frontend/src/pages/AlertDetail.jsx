import React, { useState } from "react"
import { useParams, Link } from "react-router-dom"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "react-hot-toast"
import {
  ArrowLeft,
  ShieldAlert,
  Server,
  FileCode,
  Copy,
  Download,
  CheckCircle2,
  XCircle,
  Eye,
  Bot,
  Layers,
  Clock,
} from "lucide-react"

import ScoreBreakdown from "../components/ScoreBreakdown"
import InfraGraph from "../components/InfraGraph"
import {
  getAlert,
  getAlertGraph,
  getAlertYara,
  getAlertAudit,
  confirmAlert,
  rejectAlert,
} from "../lib/api"

export default function AlertDetail() {
  const { id } = useParams()
  const queryClient = useQueryClient()
  const [justification, setJustification] = useState("")

  // Query: Alert details
  const { data: alert, isLoading, isError } = useQuery({
    queryKey: ["alert", id],
    queryFn: () => getAlert(id),
    staleTime: 5 * 60 * 1000,
    retry: 1,
  })

  // Query: Graph data
  const { data: graphData } = useQuery({
    queryKey: ["alertGraph", id],
    queryFn: () => getAlertGraph(id),
    enabled: !!alert,
    staleTime: 10 * 60 * 1000,
    retry: false,
  })

  // Query: YARA rule text
  const { data: yaraText } = useQuery({
    queryKey: ["alertYara", id],
    queryFn: () => getAlertYara(id),
    enabled: !!alert,
    staleTime: 10 * 60 * 1000,
    retry: false,
  })

  // Query: Audit log
  const { data: auditTrail } = useQuery({
    queryKey: ["alertAudit", id],
    queryFn: () => getAlertAudit(id),
    enabled: !!alert,
    staleTime: 60 * 1000,
    retry: false,
  })

  // Mutation: Confirm
  const confirmMutation = useMutation({
    mutationFn: () =>
      confirmAlert({
        alert_id: id,
        analyst_id: "soc_analyst_lead",
        justification: justification.trim() || "Confirmed malicious threat infrastructure staging impersonation attack.",
      }),
    onSuccess: () => {
      toast.success("Alert confirmed malicious! Dispatched to CERT-In, URLhaus, and STIX.")
      queryClient.invalidateQueries(["alert", id])
      queryClient.invalidateQueries(["alertAudit", id])
    },
    onError: (err) => toast.error(`Confirmation failed: ${err.message}`),
  })

  // Mutation: Reject
  const rejectMutation = useMutation({
    mutationFn: () =>
      rejectAlert({
        alert_id: id,
        analyst_id: "soc_analyst_lead",
        justification: justification.trim() || "Benign authorized domain / false positive.",
        reason_code: "known_whitelist",
      }),
    onSuccess: () => {
      toast.success("Alert marked as false positive.")
      queryClient.invalidateQueries(["alert", id])
      queryClient.invalidateQueries(["alertAudit", id])
    },
    onError: (err) => toast.error(`Rejection failed: ${err.message}`),
  })

  const copyToClipboard = (text, label) => {
    navigator.clipboard.writeText(text)
    toast.success(`${label} copied to clipboard!`)
  }

  const downloadYara = (text, filename) => {
    const blob = new Blob([text], { type: "text/plain" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = filename || "rule.yar"
    a.click()
    URL.revokeObjectURL(url)
    toast.success("YARA rule downloaded!")
  }

  if (isLoading) {
    return (
      <div className="flex justify-center items-center py-20 text-gray-400 space-x-2">
        <span className="w-3 h-3 rounded-full bg-cyan-400 animate-ping" />
        <span>Loading threat telemetry dossier...</span>
      </div>
    )
  }

  if (isError || !alert) {
    return (
      <div className="p-8 text-center bg-navy-900 border border-navy-700 rounded-xl space-y-4">
        <p className="text-red-400 font-bold">Threat alert record '{id}' could not be retrieved.</p>
        <Link to="/alerts" className="text-xs text-cyan-400 underline">
          &larr; Return to Alerts Stream
        </Link>
      </div>
    )
  }

  const signals = alert.signals || {}
  const advisoryDraft =
    alert.advisory_draft ||
    `CERT-In Advisory Draft | Reference: CERT-In/2026/GARUDA\nTarget Domain: ${alert.domain}\nScore: ${alert.score}/100\nSector: ${alert.sector}\nHosting IP: ${alert.hosting_ip || "N/A"}\n\nRECOMMENDED ACTIONS:\n1. DNS sinkholing on ${alert.domain}\n2. Revoke active auth tokens\n3. Deploy EDR hunting rules`

  return (
    <div className="space-y-6 pb-12">
      {/* Navigation & Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <Link to="/alerts" className="text-xs font-semibold text-gray-400 hover:text-cyan-400 flex items-center space-x-1.5 transition-colors">
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to All Alerts</span>
        </Link>

        <div className="flex items-center space-x-2">
          {alert.status !== "confirmed" && (
            <button
              onClick={() => confirmMutation.mutate()}
              disabled={confirmMutation.isPending}
              className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold text-xs flex items-center space-x-1.5 shadow-lg shadow-red-600/30"
            >
              <CheckCircle2 className="w-4 h-4" />
              <span>Confirm Malicious</span>
            </button>
          )}
          {alert.status !== "false_positive" && (
            <button
              onClick={() => rejectMutation.mutate()}
              disabled={rejectMutation.isPending}
              className="px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-gray-600 text-gray-200 font-semibold text-xs flex items-center space-x-1.5"
            >
              <XCircle className="w-4 h-4" />
              <span>Mark False Positive</span>
            </button>
          )}
        </div>
      </div>

      {/* Target Domain Title Card */}
      <div className="bg-navy-900 border border-navy-700 rounded-2xl p-6 shadow-2xl space-y-4">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <div className="flex items-center space-x-3">
              <h1 className="text-2xl font-black font-mono tracking-tight text-white">{alert.domain}</h1>
              <span className={`px-2.5 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider border ${
                alert.status === "confirmed" ? "bg-red-950 text-red-400 border-red-800" : "bg-amber-950 text-amber-300 border-amber-800"
              }`}>
                {alert.status}
              </span>
            </div>
            <p className="text-xs text-gray-400 mt-1">
              Detected on {new Date(alert.detected_at || Date.now()).toUTCString()} | Threat Category: <b className="text-gray-200">{alert.sector || "National Defence"}</b>
            </p>
          </div>

          <div className="flex items-center space-x-4 bg-navy-950/80 px-4 py-2.5 rounded-xl border border-navy-800">
            <div>
              <p className="text-[10px] uppercase text-gray-500 font-bold">Registrar</p>
              <p className="text-xs font-semibold text-gray-200">{alert.registrar || "Redacted"}</p>
            </div>
            <div className="w-[1px] h-8 bg-navy-800" />
            <div>
              <p className="text-[10px] uppercase text-gray-500 font-bold">Hosting IP / ASN</p>
              <p className="text-xs font-mono text-cyan-400">{alert.hosting_ip || "Unresolved"} {alert.hosting_asn && `(AS${alert.hosting_asn})`}</p>
            </div>
          </div>
        </div>

        {/* Score Breakdown Bar */}
        <ScoreBreakdown score={alert.score} signals={signals} />
      </div>

      {/* LLM Narrative Section */}
      {alert.llm_narrative && (
        <div className="bg-navy-900/90 border border-blue-500/30 rounded-2xl p-5 shadow-xl space-y-2 relative overflow-hidden">
          <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-cyan-400">
            <Bot className="w-4 h-4" />
            <span>AI Executive Threat Assessment</span>
          </div>
          <blockquote className="border-l-2 border-cyan-400 pl-4 py-1 text-xs text-gray-300 italic leading-relaxed">
            {alert.llm_narrative}
          </blockquote>
        </div>
      )}

      {/* Graph & Visual Artifacts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* D3 Graph (2 cols) */}
        <div className="lg:col-span-2 bg-navy-900 border border-navy-700 rounded-2xl p-5 shadow-xl space-y-3 flex flex-col">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-blue-400" />
              <span>4-Pivot Infrastructure Correlation Graph</span>
            </h3>
            <span className="text-[11px] text-gray-500">Scroll to zoom • Drag to pan/reposition</span>
          </div>
          <div className="flex-1 min-h-[400px]">
            <InfraGraph graphData={graphData || { nodes: [{ id: alert.domain, type: "domain" }], edges: [] }} />
          </div>
        </div>

        {/* Visual Screenshot (1 col) */}
        <div className="bg-navy-900 border border-navy-700 rounded-2xl p-5 shadow-xl space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 flex items-center gap-1.5">
            <Eye className="w-4 h-4 text-purple-400" />
            <span>Visual Evidence Snapshot</span>
          </h3>
          {alert.screenshot_url ? (
            <div className="rounded-xl overflow-hidden border border-navy-800 shadow-lg">
              <img
                src={alert.screenshot_url}
                alt="Threat domain render"
                className="w-full h-auto object-cover hover:scale-105 transition-transform"
              />
            </div>
          ) : (
            <div className="h-64 rounded-xl border border-dashed border-navy-700 bg-navy-950 flex flex-col justify-center items-center text-center p-4 space-y-2">
              <Server className="w-8 h-8 text-gray-600" />
              <p className="text-xs text-gray-400">No visual landing page screenshot captured.</p>
              <p className="text-[10px] text-gray-600">Generated on analyst confirmation</p>
            </div>
          )}
        </div>
      </div>

      {/* CERT-In Advisory & YARA Rule Sections */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* CERT-In Advisory */}
        <div className="bg-navy-900 border border-navy-700 rounded-2xl p-5 shadow-xl space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              <span>CERT-In Advisory Draft</span>
            </h3>
            <button
              onClick={() => copyToClipboard(advisoryDraft, "CERT-In Advisory")}
              className="px-2.5 py-1 rounded bg-navy-800 hover:bg-navy-700 text-cyan-300 text-xs flex items-center space-x-1 border border-navy-600"
            >
              <Copy className="w-3 h-3" />
              <span>Copy Text</span>
            </button>
          </div>
          <textarea
            readOnly
            value={advisoryDraft}
            rows={12}
            className="w-full bg-navy-950 border border-navy-800 rounded-xl p-3 font-mono text-[11px] text-gray-300 leading-relaxed focus:outline-none resize-none"
          />
        </div>

        {/* YARA Rule */}
        <div className="bg-navy-900 border border-navy-700 rounded-2xl p-5 shadow-xl space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 flex items-center gap-1.5">
              <FileCode className="w-4 h-4 text-emerald-400" />
              <span>Endpoint Forensic YARA Rule</span>
            </h3>
            <button
              onClick={() => downloadYara(yaraText || "", `APT36_${alert.domain}.yar`)}
              className="px-2.5 py-1 rounded bg-emerald-700 hover:bg-emerald-600 text-white text-xs flex items-center space-x-1"
            >
              <Download className="w-3 h-3" />
              <span>Download .yar</span>
            </button>
          </div>
          <pre className="w-full bg-navy-950 border border-navy-800 rounded-xl p-3 font-mono text-[11px] text-emerald-300 overflow-x-auto h-[252px]">
            {yaraText || "rule APT36_indicator {\n    meta:\n        author = \"GARUDA\"\n    condition:\n        any of them\n}"}
          </pre>
        </div>
      </div>

      {/* Audit Log Timeline */}
      <div className="bg-navy-900 border border-navy-700 rounded-2xl p-5 shadow-xl space-y-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 flex items-center gap-1.5">
          <Clock className="w-4 h-4 text-cyan-400" />
          <span>Immutable Audit Log & Analyst History</span>
        </h3>
        {auditTrail && auditTrail.length > 0 ? (
          <div className="divide-y divide-navy-800 font-mono text-xs">
            {auditTrail.map((entry) => (
              <div key={entry.id || entry.created_at} className="py-2.5 flex justify-between items-center text-gray-300">
                <div>
                  <span className="text-cyan-400 font-bold uppercase">{entry.action}: </span>
                  <span>{entry.justification}</span>
                </div>
                <div className="text-[10px] text-gray-500">
                  {new Date(entry.created_at).toLocaleString()} • {entry.analyst_id || "analyst"}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-gray-500 italic">No analyst actions recorded yet for this alert.</p>
        )}
      </div>
    </div>
  )
}
