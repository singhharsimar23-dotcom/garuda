import React, { useEffect, useState } from "react"
import { Link } from "react-router-dom"
import {
  Network as NetworkIcon,
  Download,
  Trash2,
  AlertTriangle,
  ExternalLink,
  Code,
  X,
  Info,
  ShieldCheck,
  ShieldBan,
} from "lucide-react"

import SectionHeader from "../components/ui/SectionHeader"
import DataTable from "../components/ui/DataTable"
import ConfidencePill from "../components/ui/ConfidencePill"
import CopyField from "../components/ui/CopyField"
import TimeAgo from "../components/ui/TimeAgo"
import EmptyState from "../components/ui/EmptyState"
import { toast } from "react-hot-toast"

export default function Network() {
  const [rpzEntries, setRpzEntries] = useState([])
  const [pdnsObs, setPdnsObs] = useState([])
  const [loadingRpz, setLoadingRpz] = useState(true)
  const [loadingPdns, setLoadingPdns] = useState(true)
  const [zoneSerial, setZoneSerial] = useState("")

  // Removal Modal State
  const [removingEntry, setRemovingEntry] = useState(null)
  const [removalReason, setRemovalReason] = useState("")
  const [isRemoving, setIsRemoving] = useState(false)

  // Raw Response Viewer Modal State
  const [inspectingRaw, setInspectingRaw] = useState(null)

  // Fetch RPZ Entries
  const fetchRpz = () => {
    setLoadingRpz(true)
    fetch("/api/rpz/entries?limit=500")
      .then((r) => r.json())
      .then((data) => {
        const list = Array.isArray(data?.entries) ? data.entries : []
        setRpzEntries(list)
        // Compute serial estimate
        const now = new Date()
        const ymd = now.toISOString().slice(0, 10).replace(/-/g, "")
        setZoneSerial(`${ymd}01`)
        setLoadingRpz(false)
      })
      .catch((e) => {
        console.warn("[Network] RPZ fetch error:", e)
        setLoadingRpz(false)
      })
  }

  // Fetch Passive DNS Matches
  const fetchPdns = () => {
    setLoadingPdns(true)
    fetch("/api/pdns/matches?limit=500")
      .then((r) => r.json())
      .then((data) => {
        const list = Array.isArray(data?.observations)
          ? data.observations
          : Array.isArray(data?.matches)
          ? data.matches
          : []
        setPdnsObs(list)
        setLoadingPdns(false)
      })
      .catch((e) => {
        console.warn("[Network] pDNS fetch error:", e)
        setLoadingPdns(false)
      })
  }

  useEffect(() => {
    fetchRpz()
    fetchPdns()
  }, [])

  // Handle RPZ removal submission
  const handleConfirmRemoval = async () => {
    if (!removingEntry) return
    if (!removalReason.trim() || removalReason.trim().length < 20) {
      toast.error("A detailed justification of at least 20 characters is required.")
      return
    }

    setIsRemoving(true)
    try {
      const res = await fetch(`/api/rpz/entries/${removingEntry.id || removingEntry.domain}/remove`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: removalReason.trim() }),
      })
      if (res.ok) {
        toast.success(`Domain ${removingEntry.domain} removed from RPZ zone`)
        setRemovingEntry(null)
        setRemovalReason("")
        fetchRpz()
      } else {
        const err = await res.json().catch(() => ({}))
        toast.error(`Removal failed: ${err.detail || "Server error"}`)
      }
    } catch (e) {
      toast.error(`Removal error: ${e.message}`)
    } finally {
      setIsRemoving(false)
    }
  }

  // RPZ DataTable Columns
  const rpzColumns = [
    {
      key: "domain",
      label: "Domain",
      mono: true,
      render: (v) => <CopyField value={v} />,
    },
    {
      key: "action",
      label: "Action",
      mono: true,
      width: "w-20",
      render: (v) => {
        const act = (v || "nxdomain").toUpperCase()
        return act === "NXDOMAIN" ? (
          <span className="bg-critical text-white font-data text-2xs font-bold px-1.5 py-0.5">
            NXDOMAIN
          </span>
        ) : (
          <span className="bg-low text-void font-data text-2xs font-bold px-1.5 py-0.5">
            PASSTHRU
          </span>
        )
      },
    },
    {
      key: "confidence",
      label: "Confidence",
      mono: true,
      width: "w-28",
      render: (v) => (
        <ConfidencePill
          confidence={v ?? 80}
          methodology="Multi-source corroboration + reputation analysis"
        />
      ),
    },
    {
      key: "sources",
      label: "Sources",
      mono: true,
      width: "w-16",
      render: (v, row) => {
        const srcList = Array.isArray(row.sources) ? row.sources.join(", ") : "GARUDA Sensor Array"
        const count = Array.isArray(row.sources) ? row.sources.length : (row.sources_count || 2)
        return (
          <span title={srcList} className="font-data text-xs text-primary font-bold">
            {count}
          </span>
        )
      },
    },
    {
      key: "added_at",
      label: "Added",
      mono: false,
      render: (v) => <TimeAgo timestamp={v} />,
    },
    {
      key: "expires_at",
      label: "Expires",
      mono: false,
      render: (v) => {
        if (!v) return <span className="text-ghost font-data text-xs">90d policy</span>
        const diffMs = new Date(v).getTime() - Date.now()
        const diffDays = diffMs / (1000 * 60 * 60 * 24)
        const isUrgent = diffDays <= 1
        const isWarning = diffDays <= 7

        return (
          <span
            className={`font-data text-xs ${
              isUrgent ? "text-critical font-bold animate-pulse" : isWarning ? "text-medium font-semibold" : "text-secondary"
            }`}
          >
            <TimeAgo timestamp={v} />
          </span>
        )
      },
    },
    {
      key: "source_stix_object_id",
      label: "Source Indicator",
      mono: true,
      render: (v) =>
        v ? (
          <Link
            to="/intelligence"
            className="inline-flex items-center gap-1 text-xs text-info hover:text-primary underline truncate max-w-[120px]"
            title={v}
          >
            <ExternalLink className="w-3 h-3 shrink-0" />
            <span className="truncate">{v}</span>
          </Link>
        ) : (
          <span className="text-ghost text-xs font-data">—</span>
        ),
    },
    {
      key: "actions",
      label: "Remove",
      sortable: false,
      width: "w-16",
      render: (_, row) => (
        <button
          onClick={(e) => {
            e.stopPropagation()
            setRemovingEntry(row)
            setRemovalReason("")
          }}
          className="text-ghost hover:text-critical transition-colors p-1"
          title="Remove from RPZ zone"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      ),
    },
  ]

  // pDNS DataTable Columns
  const pdnsColumns = [
    {
      key: "queried_domain",
      label: "Domain",
      mono: true,
      render: (v) => <CopyField value={v} />,
    },
    {
      key: "org_name",
      label: "Org Netblock",
      mono: false,
      render: (v, row) => (
        <span className="text-primary font-semibold text-xs truncate max-w-[130px] block" title={v || "Defence Netblock"}>
          {v || "Documented Netblock"}
        </span>
      ),
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
      render: (v) => <TimeAgo timestamp={v} />,
    },
    {
      key: "confidence",
      label: "Confidence",
      mono: true,
      render: (v) => (
        <ConfidencePill
          confidence={v ?? 80}
          methodology="Source STIX indicator confidence"
        />
      ),
    },
    {
      key: "verify",
      label: "Verify",
      sortable: false,
      render: (_, row) => (
        <button
          onClick={(e) => {
            e.stopPropagation()
            setInspectingRaw(row)
          }}
          className="text-2xs font-data font-bold bg-medium/20 text-medium hover:bg-medium/30 border border-medium/50 px-2 py-0.5 transition-colors"
        >
          Review Raw
        </button>
      ),
    },
  ]

  return (
    <div className="py-6 px-6 relative flex flex-col min-h-screen">
      {/* Page Title */}
      <SectionHeader
        title="Network Controls & DNS Observability"
        subtitle="Sovereign RPZ feed generation for BIND 9 resolvers and passive DNS historical correlation across defence netblocks."
      />

      {/* Split Layout: Left 60% RPZ, Right 40% pDNS */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* ========================================================================= */}
        {/* LEFT (60% / 7 cols) — DNS Response Policy Zone */}
        {/* ========================================================================= */}
        <div className="lg:col-span-7 flex flex-col space-y-4">
          <SectionHeader
            title="Response Policy Zone"
            subtitle={`${rpzEntries.length} active blocklist policies`}
            action={
              <a
                href="/api/rpz/zone.txt"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 text-2xs font-semibold text-primary hover:text-white border border-border px-3 py-1.5 bg-surface hover:bg-raised transition-colors"
              >
                <Download className="w-3.5 h-3.5 text-saffron" />
                <span>Download Zone File</span>
                {zoneSerial && <span className="text-ghost font-data">({zoneSerial})</span>}
              </a>
            }
          />

          {/* Policy Invariant Banner */}
          <div className="p-3 bg-void border border-border flex items-start justify-between text-2xs text-secondary font-data">
            <div className="flex items-start gap-2">
              <Info className="w-4 h-4 text-saffron shrink-0 mt-0.5" />
              <div>
                <span className="text-primary font-bold">Publishing Rule: </span>
                Confidence ≥ <span className="text-saffron font-bold">80</span> corroborated by ≥ <span className="text-saffron font-bold">2</span> sources.
                <p className="text-ghost mt-0.5">
                  Thresholds are enforced via code invariants to safeguard DNS resolver stability.
                </p>
              </div>
            </div>
          </div>

          {/* RPZ Table */}
          {loadingRpz ? (
            <p className="text-xs text-ghost py-10 text-center">Loading RPZ entries…</p>
          ) : rpzEntries.length === 0 ? (
            <EmptyState
              icon={NetworkIcon}
              title="No domains meet publishing threshold"
              message="No domains currently meet the publishing threshold (confidence ≥ 80, corroborated by ≥ 2 sources). Entries appear here automatically when confirmed indicators cross the threshold."
              collectionNote="Active RPZ entries expire automatically after 90 days if not re-corroborated."
            />
          ) : (
            <DataTable
              columns={rpzColumns}
              rows={rpzEntries.map((r, idx) => ({ ...r, id: r.id ?? r.domain ?? idx }))}
              sortable
            />
          )}
        </div>

        {/* ========================================================================= */}
        {/* RIGHT (40% / 5 cols) — Passive DNS Correlation */}
        {/* ========================================================================= */}
        <div className="lg:col-span-5 flex flex-col space-y-4">
          <SectionHeader
            title="Passive DNS Overlap"
            subtitle={`${pdnsObs.length} historical resolution intersections`}
          />

          {/* NON-NEGOTIABLE PERMANENT DISCLAIMER BOX */}
          <div className="border border-yellow-900 bg-yellow-950/30 text-yellow-200 text-xs p-3 leading-relaxed">
            <div className="flex items-start gap-2">
              <span className="text-yellow-400 font-bold text-sm leading-none">⚠</span>
              <p>
                These observations show historical DNS resolution overlap between confirmed C2 infrastructure and monitored IP ranges. 
                They <b>do not confirm</b> that an internal host queried a C2 domain. Manual verification is required before any action is taken.
              </p>
            </div>
          </div>

          {/* pDNS Observations Table */}
          {loadingPdns ? (
            <p className="text-xs text-ghost py-10 text-center">Loading passive DNS correlation telemetry…</p>
          ) : pdnsObs.length === 0 ? (
            <EmptyState
              icon={NetworkIcon}
              title="No passive DNS overlap observed"
              message="Passive DNS correlation detects when a known threat indicator historically resolved to an IP within monitored defence netblocks."
              collectionNote="Absence of pDNS overlap is the expected baseline for healthy sovereign infrastructure."
            />
          ) : (
            <DataTable
              columns={pdnsColumns}
              rows={pdnsObs.map((o, idx) => ({ ...o, id: o.id ?? idx }))}
              sortable
            />
          )}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* REMOVAL JUSTIFICATION MODAL */}
      {/* ========================================================================= */}
      {removingEntry && (
        <div className="fixed inset-0 bg-void/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface border border-border max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <h3 className="text-sm font-bold text-primary flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-critical" />
                <span>Remove Domain from Sovereign RPZ</span>
              </h3>
              <button onClick={() => setRemovingEntry(null)} className="text-ghost hover:text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-secondary leading-relaxed">
              Remove <code className="text-saffron font-bold font-data bg-void px-1 py-0.5">{removingEntry.domain}</code> from RPZ? 
              This will permit recursive DNS resolvers across subscribing defence networks to resolve this domain again.
            </p>

            <div className="space-y-1.5">
              <label className="text-2xs text-secondary font-semibold uppercase tracking-wider block">
                Mandatory Analyst Justification (min 20 characters):
              </label>
              <textarea
                value={removalReason}
                onChange={(e) => setRemovalReason(e.target.value)}
                placeholder="e.g. Verified legitimate research institution domain mistakenly sinkholed due to shared hosting IP overlap..."
                rows={4}
                className="w-full bg-void border border-border p-3 text-xs text-primary font-data focus:outline-none focus:border-saffron resize-none"
              />
              <div className="flex justify-between text-2xs text-ghost font-data">
                <span>Required for cryptographic audit trail</span>
                <span className={removalReason.trim().length >= 20 ? "text-low" : "text-ghost"}>
                  {removalReason.trim().length}/20 min chars
                </span>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setRemovingEntry(null)}
                disabled={isRemoving}
                className="px-3 py-1.5 border border-border text-xs text-secondary hover:text-primary bg-surface transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmRemoval}
                disabled={isRemoving || removalReason.trim().length < 20}
                className="px-3 py-1.5 bg-critical hover:bg-critical/80 text-white text-xs font-bold font-data transition-colors disabled:opacity-50"
              >
                {isRemoving ? "Removing..." : "Remove with Justification"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* RAW RESPONSE VIEWER MODAL */}
      {/* ========================================================================= */}
      {inspectingRaw && (
        <div className="fixed inset-0 bg-void/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface border border-border max-w-2xl w-full p-6 space-y-4 shadow-2xl max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center gap-2">
                <Code className="w-4 h-4 text-saffron" />
                <h3 className="text-sm font-bold text-primary font-data">
                  Raw Resolution Telemetry — {inspectingRaw.queried_domain}
                </h3>
              </div>
              <button onClick={() => setInspectingRaw(null)} className="text-ghost hover:text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="text-2xs font-data text-secondary">
              Source: <b className="text-primary uppercase">{inspectingRaw.resolved_via || "robtex"}</b> | 
              Observed: <b className="text-primary">{inspectingRaw.observed_at}</b>
            </div>

            <pre className="p-4 bg-void border border-border text-primary font-data text-xs overflow-auto flex-1 leading-relaxed">
              {JSON.stringify(inspectingRaw.raw_response || inspectingRaw, null, 2)}
            </pre>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setInspectingRaw(null)}
                className="px-4 py-1.5 border border-border text-xs text-primary bg-surface hover:bg-raised transition-colors"
              >
                Close Dossier
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
