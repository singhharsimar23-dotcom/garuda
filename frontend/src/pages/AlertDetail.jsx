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
  const [activeTab, setActiveTab] = useState("overview")

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

  // Query: pDNS matches for this alert
  const { data: pdnsData } = useQuery({
    queryKey: ["alertPdnsMatches", id],
    queryFn: async () => {
      const res = await fetch(`/api/pdns/matches/${id}`)
      if (!res.ok) return { observations: [] }
      return res.json()
    },
    enabled: !!alert,
    staleTime: 5 * 60 * 1000,
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
      queryClient.setQueryData(["alert", id], (old) => old ? { ...old, status: "confirmed" } : old)
      queryClient.invalidateQueries({ queryKey: ["alert", id] })
      queryClient.invalidateQueries({ queryKey: ["alertAudit", id] })
      queryClient.invalidateQueries({ queryKey: ["alerts"] })
      queryClient.invalidateQueries({ queryKey: ["alertsList"] })
      queryClient.invalidateQueries({ queryKey: ["stats"] })
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
      queryClient.setQueryData(["alert", id], (old) => old ? { ...old, status: "false_positive" } : old)
      queryClient.invalidateQueries({ queryKey: ["alert", id] })
      queryClient.invalidateQueries({ queryKey: ["alertAudit", id] })
      queryClient.invalidateQueries({ queryKey: ["alerts"] })
      queryClient.invalidateQueries({ queryKey: ["alertsList"] })
      queryClient.invalidateQueries({ queryKey: ["stats"] })
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
      <div className="p-8 text-center bg-surface border border-border space-y-4">
        <p className="text-critical font-bold">Threat alert record '{id}' could not be retrieved.</p>
        <Link to="/alerts" className="text-xs text-info underline">
          &larr; Return to Alerts Stream
        </Link>
      </div>
    )
  }

  const pdnsObservations = Array.isArray(pdnsData?.observations) ? pdnsData.observations : []
  const signals = alert.signals || {}
  const advisoryDraft =
    alert.advisory_draft ||
    `CERT-In Advisory Draft | Reference: CERT-In/2026/GARUDA\nTarget Domain: ${alert.domain}\nScore: ${alert.score}/100\nSector: ${alert.sector}\nHosting IP: ${alert.hosting_ip || "N/A"}\n\nRECOMMENDED ACTIONS:\n1. DNS sinkholing on ${alert.domain}\n2. Revoke active auth tokens\n3. Deploy EDR hunting rules`

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "graph", label: "Infrastructure Graph" },
    { id: "advisory", label: "Advisory" },
    { id: "yara", label: "YARA" },
    { id: "audit", label: "Audit" },
    { id: "network_overlap", label: "Network Overlap" },
  ]

  const pdnsColumns = [
    {
      key: "queried_domain",
      label: "Domain",
      mono: true,
      render: (v) => <span className="font-data font-bold text-xs text-primary">{v}</span>,
    },
    {
      key: "org_name",
      label: "Org Netblock",
      mono: false,
      render: (v) => <span className="text-primary font-semibold text-xs">{v || "Documented Netblock"}</span>,
    },
    {
      key: "resolved_via",
      label: "Via",
      mono: true,
      render: (v) => (
        <span className="bg-raised border border-border text-2xs font-data text-secondary uppercase px-1.5 py-0.5">
          {v || "robtex"}
        </span>
      ),
    },
    {
      key: "observed_at",
      label: "Observed",
      mono: false,
      render: (v) => <span className="font-data text-xs text-secondary">{v ? v.split("T")[0] : "—"}</span>,
    },
    {
      key: "confidence",
      label: "Confidence",
      mono: true,
      render: (v) => (
        <span className="font-data text-xs text-primary font-bold">{v ?? 80}%</span>
      ),
    },
  ]

  return (
    <div className="space-y-6 pb-12">
      {/* Navigation & Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <Link to="/alerts" className="text-xs font-semibold text-secondary hover:text-primary flex items-center space-x-1.5 transition-colors">
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to All Alerts</span>
        </Link>

        <div className="flex items-center space-x-2">
          {alert.status !== "confirmed" && (
            <button
              onClick={() => confirmMutation.mutate()}
              disabled={confirmMutation.isPending}
              className="px-3 py-1.5 bg-critical hover:bg-critical/80 text-white font-semibold text-xs flex items-center space-x-1.5 shadow-lg"
            >
              <CheckCircle2 className="w-4 h-4" />
              <span>Confirm Malicious</span>
            </button>
          )}
          {alert.status !== "false_positive" && (
            <button
              onClick={() => rejectMutation.mutate()}
              disabled={rejectMutation.isPending}
              className="px-3 py-1.5 bg-surface hover:bg-raised text-secondary hover:text-primary border border-border font-semibold text-xs flex items-center space-x-1.5"
            >
              <XCircle className="w-4 h-4" />
              <span>Mark False Positive</span>
            </button>
          )}
        </div>
      </div>

      {/* Target Domain Title Card */}
      <div className="bg-surface border border-border p-6 space-y-4">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <div className="flex items-center space-x-3">
              <h1 className="text-2xl font-bold font-data text-primary">{alert.domain}</h1>
              <span className={`px-2 py-0.5 text-2xs font-bold font-data uppercase tracking-wider border ${
                alert.status === "confirmed" ? "bg-critical/20 text-critical border-critical" : "bg-gold/20 text-gold border-gold"
              }`}>
                {alert.status}
              </span>
            </div>
            <p className="text-xs text-secondary mt-1">
              Detected on {new Date(alert.detected_at || Date.now()).toUTCString()} | Threat Category: <b className="text-primary">{alert.sector || "National Defence"}</b>
            </p>
          </div>

          <div className="flex items-center space-x-4 bg-void px-4 py-2.5 border border-border">
            <div>
              <p className="text-2xs uppercase text-secondary font-bold font-data">Registrar</p>
              <p className="text-xs font-semibold text-primary">{alert.registrar || "Redacted"}</p>
            </div>
            <div className="w-[1px] h-8 bg-border" />
            <div>
              <p className="text-2xs uppercase text-secondary font-bold font-data">Hosting IP / ASN</p>
              <p className="text-xs font-data text-saffron">{alert.hosting_ip || "Unresolved"} {alert.hosting_asn && `(AS${alert.hosting_asn})`}</p>
            </div>
          </div>
        </div>

        {/* Score Breakdown Bar */}
        <ScoreBreakdown score={alert.score} signals={signals} />
      </div>

      {/* LLM Narrative Section */}
      {alert.llm_narrative && (
        <div className="bg-surface border border-border p-4 space-y-2">
          <div className="flex items-center space-x-2 text-2xs font-bold uppercase tracking-wider text-saffron font-data">
            <Bot className="w-4 h-4" />
            <span>AI Executive Threat Assessment</span>
          </div>
          <blockquote className="border-l-2 border-saffron pl-4 py-1 text-xs text-secondary italic leading-relaxed">
            {alert.llm_narrative}
          </blockquote>
        </div>
      )}

      {/* TAB BAR */}
      <div className="flex items-center gap-1 border-b border-border bg-surface px-2">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors duration-[80ms] ${
                isActive
                  ? "border-saffron text-saffron bg-void"
                  : "border-transparent text-secondary hover:text-primary hover:bg-void/50"
              }`}
            >
              {tab.label}
            </button>
          )
        })}
      </div>

      {/* TAB CONTENT: Overview */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 bg-surface border border-border p-5 space-y-3 flex flex-col">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider text-secondary flex items-center gap-1.5">
                  <Layers className="w-4 h-4 text-saffron" />
                  <span>4-Pivot Infrastructure Correlation Preview</span>
                </h3>
                <button onClick={() => setActiveTab("graph")} className="text-2xs text-info hover:underline">
                  Full View &rarr;
                </button>
              </div>
              <div className="flex-1 min-h-[300px]">
                <InfraGraph graphData={graphData || { nodes: [{ id: alert.domain, type: "domain" }], edges: [] }} />
              </div>
            </div>

            <div className="bg-surface border border-border p-5 space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-secondary flex items-center gap-1.5">
                <Eye className="w-4 h-4 text-primary" />
                <span>Visual Evidence Snapshot</span>
              </h3>
              {alert.screenshot_url ? (
                <div className="border border-border">
                  <img
                    src={alert.screenshot_url}
                    alt="Threat domain render"
                    className="w-full h-auto object-cover"
                  />
                </div>
              ) : (
                <div className="h-48 border border-dashed border-border bg-void flex flex-col justify-center items-center text-center p-4 space-y-2">
                  <Server className="w-6 h-6 text-ghost" />
                  <p className="text-xs text-secondary">No visual landing page screenshot captured.</p>
                  <p className="text-2xs text-ghost font-data">Generated on analyst confirmation</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT: Infrastructure Graph */}
      {activeTab === "graph" && (
        <div className="bg-surface border border-border p-5 space-y-3 flex flex-col">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-secondary flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-saffron" />
              <span>4-Pivot Infrastructure Correlation Graph</span>
            </h3>
            <span className="text-2xs text-ghost font-data">Scroll to zoom • Drag to pan/reposition</span>
          </div>
          <div className="flex-1 min-h-[500px]">
            <InfraGraph graphData={graphData || { nodes: [{ id: alert.domain, type: "domain" }], edges: [] }} />
          </div>
        </div>
      )}

      {/* TAB CONTENT: Advisory */}
      {activeTab === "advisory" && (
        <div className="bg-surface border border-border p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-secondary flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-critical" />
              <span>CERT-In Advisory Draft</span>
            </h3>
            <button
              onClick={() => copyToClipboard(advisoryDraft, "CERT-In Advisory")}
              className="px-2.5 py-1 bg-void hover:bg-raised text-primary text-xs flex items-center space-x-1 border border-border"
            >
              <Copy className="w-3 h-3" />
              <span>Copy Text</span>
            </button>
          </div>
          <textarea
            readOnly
            value={advisoryDraft}
            rows={14}
            className="w-full bg-void border border-border p-3 font-data text-xs text-primary leading-relaxed focus:outline-none resize-none"
          />
        </div>
      )}

      {/* TAB CONTENT: YARA */}
      {activeTab === "yara" && (
        <div className="bg-surface border border-border p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-secondary flex items-center gap-1.5">
              <FileCode className="w-4 h-4 text-low" />
              <span>Endpoint Forensic YARA Rule</span>
            </h3>
            <button
              onClick={() => downloadYara(yaraText || "", `APT36_${alert.domain}.yar`)}
              className="px-2.5 py-1 bg-void hover:bg-raised text-low text-xs flex items-center space-x-1 border border-border font-semibold"
            >
              <Download className="w-3 h-3" />
              <span>Download .yar</span>
            </button>
          </div>
          <pre className="w-full bg-void border border-border p-3 font-data text-xs text-low overflow-x-auto h-[320px]">
            {yaraText || "rule APT36_indicator {\n    meta:\n        author = \"GARUDA\"\n    condition:\n        any of them\n}"}
          </pre>
        </div>
      )}

      {/* TAB CONTENT: Audit */}
      {activeTab === "audit" && (
        <div className="bg-surface border border-border p-5 space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-secondary flex items-center gap-1.5">
            <Clock className="w-4 h-4 text-saffron" />
            <span>Immutable Audit Log & Analyst History</span>
          </h3>
          {auditTrail && auditTrail.length > 0 ? (
            <div className="divide-y divide-border font-data text-xs">
              {auditTrail.map((entry) => (
                <div key={entry.id || entry.created_at} className="py-2.5 flex justify-between items-center text-primary">
                  <div>
                    <span className="text-saffron font-bold uppercase">{entry.action}: </span>
                    <span>{entry.justification}</span>
                  </div>
                  <div className="text-2xs text-secondary">
                    {new Date(entry.created_at).toLocaleString()} • {entry.analyst_id || "analyst"}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-ghost italic">No analyst actions recorded yet for this alert.</p>
          )}
        </div>
      )}

      {/* TAB CONTENT: Network Overlap (NEW TAB) */}
      {activeTab === "network_overlap" && (
        <div className="bg-surface border border-border p-5 space-y-4">
          <div>
            <h3 className="text-sm font-bold text-primary font-data mb-1">
              Passive DNS Resolution Overlap
            </h3>
            <p className="text-xs text-secondary">
              Correlated historical DNS resolution intersections between <code className="text-primary font-data">{alert.domain}</code> and monitored defence netblocks.
            </p>
          </div>

          {/* PERMANENT NON-DISMISSIBLE DISCLAIMER BOX */}
          <div className="border border-yellow-900 bg-yellow-950/30 text-yellow-200 text-xs p-3 leading-relaxed">
            <div className="flex items-start gap-2">
              <span className="text-yellow-400 font-bold text-sm leading-none">⚠</span>
              <p>
                These observations show historical DNS resolution overlap between confirmed C2 infrastructure and
                monitored IP ranges. They <b>do not confirm</b> that an internal host queried a C2 domain. Manual
                verification is required before any action is taken.
              </p>
            </div>
          </div>

          {pdnsLoading ? (
            <p className="text-xs text-ghost py-8 text-center font-data">Checking passive DNS correlation logs…</p>
          ) : pdnsObservations.length === 0 ? (
            <div className="py-12 px-4 text-center border border-border bg-void">
              <p className="text-xs font-semibold text-secondary mb-1">
                No passive DNS overlap observed for this indicator.
              </p>
              <p className="text-2xs text-ghost font-data max-w-md mx-auto leading-relaxed">
                This is the expected baseline state for most indicators. Overlap occurs only when adversary infrastructure historically shared resolution paths with documented sovereign defence ranges.
              </p>
            </div>
          ) : (
            <div className="border border-border">
              <table className="w-full border-collapse">
                <thead>
                  <tr className="bg-void border-b border-border text-2xs font-semibold text-secondary uppercase">
                    <th className="px-3 py-2 text-left">Domain</th>
                    <th className="px-3 py-2 text-left">Org Netblock</th>
                    <th className="px-3 py-2 text-left">Via</th>
                    <th className="px-3 py-2 text-left">Observed</th>
                    <th className="px-3 py-2 text-left">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {pdnsObservations.map((obs, idx) => (
                    <tr key={obs.id || idx} className="bg-surface hover:bg-raised transition-colors">
                      <td className="px-3 py-2 font-data text-xs text-primary">{obs.queried_domain || alert.domain}</td>
                      <td className="px-3 py-2 text-xs text-primary">{obs.org_name || "Documented Netblock"}</td>
                      <td className="px-3 py-2">
                        <span className="bg-void border border-border text-2xs font-data text-secondary uppercase px-1.5 py-0.5">
                          {obs.resolved_via || "robtex"}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-data text-xs text-secondary">{obs.observed_at ? obs.observed_at.split("T")[0] : "—"}</td>
                      <td className="px-3 py-2 font-data text-xs font-bold text-primary">{obs.confidence ?? 80}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

