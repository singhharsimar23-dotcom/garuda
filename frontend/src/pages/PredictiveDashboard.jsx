import React, { useEffect, useState } from "react"
import { Target, DollarSign, X } from "lucide-react"
import { toast } from "react-hot-toast"

import SectionHeader from "../components/ui/SectionHeader"
import DataTable from "../components/ui/DataTable"
import EmptyState from "../components/ui/EmptyState"
import TimeAgo from "../components/ui/TimeAgo"

function ScoreGauge({ score }) {
  const pct = Math.min(100, Math.round((Number(score) || 0) * 100))
  const color = pct >= 70 ? "#FF3B30" : pct >= 50 ? "#FF9500" : "#34C759"
  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="flex-1 h-1.5 bg-void border border-border">
        <div className="h-full transition-all duration-150" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="font-data text-xs font-bold" style={{ color }}>{pct}%</span>
    </div>
  )
}

export default function PredictiveDashboard() {
  const [candidates, setCandidates] = useState([])
  const [registered, setRegistered] = useState([])
  const [budget, setBudget] = useState({ monthly_limit_usd: 50, spent_usd: 0, remaining_usd: 50 })
  const [loading, setLoading] = useState(true)
  const [registerModal, setRegisterModal] = useState(null)
  const [justification, setJustification] = useState("")
  const [registering, setRegistering] = useState(false)

  const fetchData = () => {
    setLoading(true)
    fetch("/api/predictive/domains")
      .then((r) => (r.ok ? r.json() : { candidates: [], registered: [], budget: {} }))
      .then((data) => {
        setCandidates(Array.isArray(data.candidates) ? data.candidates : [])
        setRegistered(Array.isArray(data.registered) ? data.registered : [])
        setBudget(data.budget || { monthly_limit_usd: 50, spent_usd: 0, remaining_usd: 50 })
      })
      .catch(() => {
        setCandidates([])
        setRegistered([])
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => { fetchData() }, [])

  const handleRegister = async () => {
    if (!registerModal) return
    if (justification.trim().length < 30) {
      toast.error("Justification must be at least 30 characters")
      return
    }
    setRegistering(true)
    try {
      const res = await fetch("/api/predictive/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${import.meta.env.VITE_TAXII_ADMIN_TOKEN || ""}`,
        },
        body: JSON.stringify({
          domain: registerModal.domain,
          analyst_id: "soc_lead_analyst",
          justification: justification.trim(),
        }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.detail || "Registration failed")
      toast.success(`Registered ${registerModal.domain}`)
      setRegisterModal(null)
      setJustification("")
      fetchData()
    } catch (err) {
      toast.error(err.message)
    } finally {
      setRegistering(false)
    }
  }

  const candidateColumns = [
    {
      key: "domain",
      label: "Domain",
      mono: true,
      render: (v) => <span className="font-data text-primary">{v}</span>,
    },
    {
      key: "prediction_score",
      label: "Score",
      render: (v) => <ScoreGauge score={v} />,
    },
    {
      key: "narrative_keywords",
      label: "Keywords",
      render: (v) => (
        <span className="font-data text-2xs text-secondary truncate max-w-[160px] block" title={(v || []).join(", ")}>
          {(v || []).slice(0, 3).join(", ") || "—"}
        </span>
      ),
    },
    {
      key: "status",
      label: "Status",
      mono: true,
      render: (v) => (
        <span className="font-data text-2xs uppercase bg-void border border-border px-1.5 py-0.5 text-secondary">
          {v || "candidate"}
        </span>
      ),
    },
    {
      key: "actions",
      label: "Action",
      sortable: false,
      render: (_, row) => {
        const score = Number(row.prediction_score) || 0
        if (score <= 0.7) return <span className="text-ghost text-2xs">Below threshold</span>
        return (
          <button
            onClick={(e) => {
              e.stopPropagation()
              setRegisterModal(row)
              setJustification("")
            }}
            className="text-2xs font-data font-bold bg-saffron/20 text-saffron border border-saffron/40 px-2 py-1 hover:bg-saffron/30 transition-colors duration-150"
          >
            Pre-register
          </button>
        )
      },
    },
  ]

  const registeredColumns = [
    { key: "domain", label: "Domain", mono: true },
    { key: "registered_at", label: "Registered", render: (v) => <TimeAgo timestamp={v} /> },
    { key: "fire_count", label: "Fire Count", mono: true, render: (v) => <span className="font-data font-bold text-saffron">{v ?? 0}</span> },
    {
      key: "status",
      label: "Status",
      mono: true,
      render: (v) => <span className="font-data text-2xs text-low uppercase">{v || "registered"}</span>,
    },
  ]

  const budgetPct = budget.monthly_limit_usd
    ? Math.min(100, (budget.spent_usd / budget.monthly_limit_usd) * 100)
    : 0

  return (
    <div className="py-6 px-6 space-y-6 min-h-screen">
      <SectionHeader
        title="Predictive Domain Pre-Registration"
        subtitle="APT36 honeypot disruption — pre-register predicted phishing domains before adversary registration."
      />

      {/* Sovereign Deceptive Defense Radar */}
      <div className="bg-surface border border-border p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-void border border-border text-saffron">
            <Target className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 text-xs font-bold text-primary uppercase tracking-wider">
              <span>Autonomous Pre-Emptive Sinkhole Grid</span>
              <span className="px-1.5 py-0.5 text-3xs font-data bg-low/20 text-low border border-low/40 uppercase">Active</span>
            </div>
            <p className="text-2xs text-secondary mt-0.5">
              Zero-cost proactive domain disruption — predicts and sinkholes adversary phishing candidates before weaponization.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-6 text-2xs font-data border-t md:border-t-0 md:border-l border-border pt-3 md:pt-0 md:pl-6 shrink-0">
          <div>
            <div className="text-ghost uppercase text-3xs">Active Candidates</div>
            <div className="text-sm font-bold text-primary">{candidates.length}</div>
          </div>
          <div>
            <div className="text-ghost uppercase text-3xs">Armed Honeypots</div>
            <div className="text-sm font-bold text-saffron">{registered.length}</div>
          </div>
          <div>
            <div className="text-ghost uppercase text-3xs">Interceptions</div>
            <div className="text-sm font-bold text-critical">
              {registered.reduce((acc, r) => acc + (r.fire_count || 0), 0)}
            </div>
          </div>
        </div>
      </div>

      <div className="space-y-4">
        <h3 className="text-xs font-bold text-secondary uppercase tracking-widest flex items-center gap-2">
          <Target className="w-4 h-4 text-saffron" />
          Candidate Domains
        </h3>
        {loading ? (
          <p className="text-xs text-ghost py-8 text-center">Loading candidates…</p>
        ) : candidates.length === 0 ? (
          <EmptyState
            icon={Target}
            title="No predictive candidates"
            message="Run POST /api/predictive/analyze to generate scored domain candidates from ISPR narrative keywords."
          />
        ) : (
          <DataTable
            columns={candidateColumns}
            rows={candidates.map((c, i) => ({ ...c, id: c.id || c.domain || i }))}
            sortable
          />
        )}
      </div>

      <div className="space-y-4">
        <h3 className="text-xs font-bold text-secondary uppercase tracking-widest">Registered Honeypots</h3>
        {registered.length === 0 ? (
          <EmptyState
            icon={Target}
            title="No honeypots registered"
            message="Analyst-approved pre-registrations appear here after POST /api/predictive/register succeeds."
          />
        ) : (
          <DataTable
            columns={registeredColumns}
            rows={registered.map((r, i) => ({ ...r, id: r.id || r.domain || i }))}
            sortable
          />
        )}
      </div>

      {registerModal && (
        <div className="fixed inset-0 bg-void/85 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface border border-border max-w-md w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-sm font-bold text-primary">Pre-register Domain</h3>
              <button onClick={() => setRegisterModal(null)} className="text-ghost hover:text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>
            <p className="text-xs text-secondary">
              Register <code className="font-data text-saffron">{registerModal.domain}</code> as analyst-approved honeypot?
            </p>
            <textarea
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              placeholder="Mandatory analyst justification (min 30 chars)…"
              rows={4}
              className="w-full bg-void border border-border p-3 text-xs font-data text-primary focus:outline-none focus:border-saffron resize-none"
            />
            <div className="flex justify-between text-2xs font-data text-ghost">
              <span>Required for audit trail</span>
              <span className={justification.trim().length >= 30 ? "text-low" : ""}>
                {justification.trim().length}/30
              </span>
            </div>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setRegisterModal(null)}
                className="px-3 py-1.5 border border-border text-xs text-secondary"
              >
                Cancel
              </button>
              <button
                onClick={handleRegister}
                disabled={registering || justification.trim().length < 30}
                className="px-4 py-1.5 bg-saffron text-void text-xs font-bold font-data disabled:opacity-50"
              >
                {registering ? "Registering…" : "Confirm Registration"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
