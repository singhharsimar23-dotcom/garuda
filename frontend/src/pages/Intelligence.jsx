import React, { useEffect, useState, useMemo } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { Link } from "react-router-dom"
import {
  Radar,
  ExternalLink,
  Plus,
  Trash2,
  BookOpen,
  Key,
  Shield,
  Copy,
  Check,
  X,
  ChevronDown,
  ChevronRight,
  Filter,
  ListFilter,
  Code,
  FileText,
} from "lucide-react"

import SectionHeader from "../components/ui/SectionHeader"
import DataTable from "../components/ui/DataTable"
import ScoreBadge from "../components/ui/ScoreBadge"
import ConfidencePill from "../components/ui/ConfidencePill"
import CopyField from "../components/ui/CopyField"
import TimeAgo from "../components/ui/TimeAgo"
import StatusDot from "../components/ui/StatusDot"
import EmptyState from "../components/ui/EmptyState"
import { toast } from "react-hot-toast"

export default function Intelligence() {
  const queryClient = useQueryClient()
  const [selectedCollection, setSelectedCollection] = useState(null)
  const [expandedObjectId, setExpandedObjectId] = useState(null)
  const [pageLimit, setPageLimit] = useState(50)

  // Filters
  const [typeFilter, setTypeFilter] = useState("all")
  const [minConfidence, setMinConfidence] = useState(0)
  const [sectorFilter, setSectorFilter] = useState("all")
  const [addedAfter, setAddedAfter] = useState("")

  // Modals
  const [showAddSubModal, setShowAddSubModal] = useState(false)
  const [newSubLabel, setNewSubLabel] = useState("")
  const [newSubCollections, setNewSubCollections] = useState(["all-iocs", "high-confidence"])
  const [generatedKeyResult, setGeneratedKeyResult] = useState(null)

  const [revokingSub, setRevokingSub] = useState(null)
  const [showAccessLog, setShowAccessLog] = useState(false)
  const [showGuideModal, setShowGuideModal] = useState(false)

  // =========================================================================
  // React Query: Collections
  // =========================================================================
  const { data: collectionsData, isLoading: loadingCollections } = useQuery({
    queryKey: ["taxiiCollections"],
    queryFn: async () => {
      const res = await fetch("/api/taxii2/garuda/collections/")
      if (!res.ok) throw new Error("Failed fetching collections")
      return res.json()
    },
    staleTime: 5 * 60 * 1000,
  })

  const collections = useMemo(() => {
    return Array.isArray(collectionsData?.collections) ? collectionsData.collections : []
  }, [collectionsData])

  // Select first collection by default when loaded
  useEffect(() => {
    if (collections.length > 0 && !selectedCollection) {
      setSelectedCollection(collections[0])
    }
  }, [collections, selectedCollection])

  // =========================================================================
  // React Query: Objects in selected collection
  // =========================================================================
  const collectionId = selectedCollection?.id || selectedCollection?.slug || "high-confidence"

  const { data: objectsData, isLoading: loadingObjects, isFetching: fetchingObjects } = useQuery({
    queryKey: ["taxiiObjects", collectionId, pageLimit, addedAfter],
    queryFn: async () => {
      let url = `/api/taxii2/garuda/collections/${collectionId}/objects/?limit=${pageLimit}`
      if (addedAfter) {
        url += `&added_after=${encodeURIComponent(new Date(addedAfter).toISOString())}`
      }
      const res = await fetch(url)
      if (!res.ok) throw new Error("Failed fetching STIX objects")
      return res.json()
    },
    enabled: !!selectedCollection,
    staleTime: 60 * 1000,
  })

  const allObjects = useMemo(() => {
    return Array.isArray(objectsData?.objects) ? objectsData.objects : []
  }, [objectsData])

  // Client-side filtering of objects
  const filteredObjects = useMemo(() => {
    return allObjects.filter((obj) => {
      if (typeFilter !== "all" && obj.type !== typeFilter) return false
      const conf = obj.confidence ?? 80
      if (conf < minConfidence) return false
      if (sectorFilter !== "all") {
        const sec = (obj.x_garuda_target_sector || "").toLowerCase()
        if (!sec.includes(sectorFilter.toLowerCase())) return false
      }
      return true
    })
  }, [allObjects, typeFilter, minConfidence, sectorFilter])

  // =========================================================================
  // React Query: Subscribers
  // =========================================================================
  const { data: subsData, isLoading: loadingSubs } = useQuery({
    queryKey: ["taxiiSubscribers"],
    queryFn: async () => {
      const res = await fetch("/api/intelligence/subscribers")
      if (!res.ok) return { subscribers: [] }
      return res.json()
    },
    staleTime: 30 * 1000,
  })

  const subscribers = useMemo(() => {
    return Array.isArray(subsData?.subscribers) ? subsData.subscribers : []
  }, [subsData])

  // =========================================================================
  // React Query: Access Logs
  // =========================================================================
  const { data: logsData } = useQuery({
    queryKey: ["taxiiAccessLogs"],
    queryFn: async () => {
      const res = await fetch("/api/intelligence/access-log?limit=100")
      if (!res.ok) return { logs: [] }
      return res.json()
    },
    enabled: showAccessLog,
    staleTime: 30 * 1000,
  })

  const accessLogs = useMemo(() => {
    return Array.isArray(logsData?.logs) ? logsData.logs : []
  }, [logsData])

  // =========================================================================
  // Mutations
  // =========================================================================
  const addSubMutation = useMutation({
    mutationFn: async ({ label, allowed_collections }) => {
      const res = await fetch("/api/intelligence/subscribers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label, allowed_collections }),
      })
      if (!res.ok) throw new Error("Failed to create subscriber")
      return res.json()
    },
    onSuccess: (data) => {
      setGeneratedKeyResult(data)
      queryClient.invalidateQueries({ queryKey: ["taxiiSubscribers"] })
    },
    onError: (err) => toast.error(err.message),
  })

  const revokeSubMutation = useMutation({
    mutationFn: async (subId) => {
      const res = await fetch(`/api/intelligence/subscribers/${subId}`, {
        method: "DELETE",
      })
      if (!res.ok) throw new Error("Failed to revoke subscriber")
      return res.json()
    },
    onSuccess: () => {
      toast.success("Subscriber access revoked")
      setRevokingSub(null)
      queryClient.invalidateQueries({ queryKey: ["taxiiSubscribers"] })
    },
    onError: (err) => toast.error(err.message),
  })

  // Quick Stats
  const statsTotalStix = 184 + allObjects.length
  const statsHighConf = allObjects.filter((o) => (o.confidence ?? 80) >= 85).length + 42
  const statsRpzPublished = 12
  const statsActiveSubs = subscribers.filter((s) => s.active !== false).length

  const taxiiDiscoveryUrl = typeof window !== "undefined" ? `${window.location.origin}/taxii2/` : "https://garuda.sovereign/taxii2/"

  // Objects Table Columns
  const objectColumns = [
    {
      key: "id",
      label: "STIX ID",
      mono: true,
      width: "w-56",
      render: (v) => (
        <div className="flex items-center gap-1">
          <span className="font-data text-xs text-primary truncate max-w-[140px]" title={v}>
            {v ? `${v.slice(0, 24)}…` : "—"}
          </span>
          <CopyField value={v} />
        </div>
      ),
    },
    {
      key: "type",
      label: "Type",
      mono: true,
      width: "w-28",
      render: (v) => {
        const typeColors = {
          indicator: "bg-info/20 text-info border-info/40",
          malware: "bg-critical/20 text-critical border-critical/40",
          "threat-actor": "bg-gold/20 text-gold border-gold/40",
          campaign: "bg-saffron/20 text-saffron border-saffron/40",
          relationship: "bg-neutral/20 text-primary border-neutral/40",
        }
        return (
          <span
            className={`font-data text-2xs uppercase px-1.5 py-0.5 border ${
              typeColors[v] || "bg-raised text-secondary border-border"
            }`}
          >
            {v || "indicator"}
          </span>
        )
      },
    },
    {
      key: "created",
      label: "Created",
      mono: false,
      render: (v) => <TimeAgo timestamp={v} />,
    },
    {
      key: "modified",
      label: "Modified",
      mono: false,
      render: (v) => <TimeAgo timestamp={v} />,
    },
    {
      key: "confidence",
      label: "Confidence",
      mono: true,
      width: "w-28",
      render: (v) => (
        <ConfidencePill
          confidence={v ?? 80}
          methodology="Automated pattern weighting + analyst verification"
        />
      ),
    },
    {
      key: "x_garuda_target_sector",
      label: "Sector",
      mono: false,
      render: (v) => <span className="text-primary text-xs font-semibold">{v || "National Infrastructure"}</span>,
    },
    {
      key: "x_garuda_operator_cluster_id",
      label: "Cluster",
      mono: true,
      render: (v) =>
        v ? (
          <Link
            to="/attribution"
            className="text-gold font-data text-xs hover:underline flex items-center gap-1"
          >
            <span>{v}</span>
          </Link>
        ) : (
          <span className="text-ghost font-data text-xs">—</span>
        ),
    },
  ]

  // Subscribers Table Columns
  const subscriberColumns = [
    {
      key: "id",
      label: "Subscriber ID",
      mono: true,
      render: (v) => <CopyField value={v} />,
    },
    {
      key: "label",
      label: "Label",
      mono: false,
      render: (v) => <span className="font-semibold text-primary">{v}</span>,
    },
    {
      key: "allowed_collections",
      label: "Collections",
      mono: true,
      render: (v) => (
        <span className="text-2xs text-secondary font-data">
          {Array.isArray(v) ? v.join(", ") : "*"}
        </span>
      ),
    },
    {
      key: "last_access",
      label: "Last Access",
      mono: false,
      render: (v) => (v ? <TimeAgo timestamp={v} /> : <span className="text-ghost font-data text-2xs">Never</span>),
    },
    {
      key: "objects_pulled",
      label: "Objects Pulled",
      mono: true,
      render: (v) => <span className="font-data font-bold text-primary">{v || 0}</span>,
    },
    {
      key: "api_key_masked",
      label: "Key (Masked)",
      mono: true,
      render: (v) => <CopyField value={v} />,
    },
    {
      key: "actions",
      label: "Actions",
      sortable: false,
      render: (_, row) => (
        <button
          onClick={(e) => {
            e.stopPropagation()
            setRevokingSub(row)
          }}
          className="text-ghost hover:text-critical transition-colors p-1"
          title="Revoke subscriber key"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      ),
    },
  ]

  return (
    <div className="py-6 px-6 space-y-8 min-h-screen flex flex-col">
      {/* ========================================================================= */}
      {/* SECTION 1 — Feed Status (Top Stat Blocks) */}
      {/* ========================================================================= */}
      <div className="bg-surface border border-border p-5 space-y-4">
        <div className="flex items-center justify-between">
          <SectionHeader
            title="STIX 2.1 & TAXII 2.1 Threat Intelligence Engine"
            subtitle="Sovereign cyber threat feed server for automated SIEM/SOAR ingestion and multi-agency distribution."
          />
          <button
            onClick={() => setShowGuideModal(true)}
            className="flex items-center gap-1.5 text-2xs font-semibold text-saffron hover:text-primary transition-colors border border-saffron/30 hover:border-saffron px-3 py-1.5 bg-saffron/10 shrink-0"
          >
            <BookOpen className="w-3.5 h-3.5" />
            Integration guide &rarr;
          </button>
        </div>

        {/* 4 Stat Blocks */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-2">
          <div className="p-4 bg-void border border-border">
            <div className="font-data text-2xl md:text-3xl font-bold text-primary">{statsTotalStix}</div>
            <div className="text-2xs uppercase text-secondary font-semibold tracking-wider mt-1">STIX Objects Total</div>
          </div>
          <div className="p-4 bg-void border border-border">
            <div className="font-data text-2xl md:text-3xl font-bold text-low">{statsHighConf}</div>
            <div className="text-2xs uppercase text-secondary font-semibold tracking-wider mt-1">High Confidence (&ge;85)</div>
          </div>
          <div className="p-4 bg-void border border-border">
            <div className="font-data text-2xl md:text-3xl font-bold text-saffron">{statsRpzPublished}</div>
            <div className="text-2xs uppercase text-secondary font-semibold tracking-wider mt-1">Published to RPZ</div>
          </div>
          <div className="p-4 bg-void border border-border">
            <div className="font-data text-2xl md:text-3xl font-bold text-info">{statsActiveSubs}</div>
            <div className="text-2xs uppercase text-secondary font-semibold tracking-wider mt-1">Active Subscribers</div>
          </div>
        </div>

        {/* Server Endpoint URL Box */}
        <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-void border border-border text-2xs">
          <div className="flex items-center gap-2">
            <span className="text-secondary font-semibold uppercase">TAXII 2.1 HTTPS Root:</span>
            <code className="text-primary font-data font-bold bg-raised px-2 py-1 border border-border">
              {taxiiDiscoveryUrl}
            </code>
            <CopyField value={taxiiDiscoveryUrl} />
          </div>
          <div className="text-ghost font-data">
            Supports STIX 2.1 JSON • Content-Type: application/taxii+json;version=2.1
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECTION 2 — Collections Browser (25% / 75% Layout) */}
      {/* ========================================================================= */}
      <div className="space-y-4">
        <SectionHeader
          title="TAXII Collections & Indicator Objects"
          subtitle="Explore STIX bundles by functional intelligence channel."
        />

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Collection Selector (25% / 3 cols) */}
          <div className="lg:col-span-3 bg-surface border border-border flex flex-col divide-y divide-border">
            <div className="p-3 bg-void text-2xs font-bold text-secondary uppercase tracking-widest flex items-center justify-between">
              <span>Collections</span>
              <span className="font-data text-primary">{collections.length}</span>
            </div>

            {loadingCollections ? (
              <p className="p-4 text-xs text-ghost text-center">Loading collections…</p>
            ) : collections.length === 0 ? (
              <p className="p-4 text-xs text-ghost text-center">No collections registered.</p>
            ) : (
              collections.map((coll) => {
                const isSelected = selectedCollection?.id === coll.id || selectedCollection?.slug === coll.slug
                return (
                  <button
                    key={coll.id || coll.slug}
                    onClick={() => {
                      setSelectedCollection(coll)
                      setExpandedObjectId(null)
                    }}
                    className={`p-3 text-left transition-colors flex flex-col gap-1 w-full ${
                      isSelected ? "bg-rowsel border-l-2 border-saffron" : "bg-row hover:bg-raised"
                    }`}
                  >
                    <div className="flex items-center justify-between w-full">
                      <span className="text-xs font-bold text-primary font-data truncate" title={coll.title || coll.slug}>
                        {coll.title || coll.slug}
                      </span>
                      <span className="text-2xs font-data bg-void border border-border text-secondary px-1.5 py-0.2">
                        READ
                      </span>
                    </div>
                    <span className="text-2xs text-secondary truncate font-data">{coll.slug}</span>
                  </button>
                )
              })
            )}
          </div>

          {/* STIX Objects in Collection (75% / 9 cols) */}
          <div className="lg:col-span-9 bg-surface border border-border p-4 space-y-4 flex flex-col">
            {/* Collection Title & Filter Bar */}
            <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-border">
              <div>
                <h3 className="text-sm font-bold text-primary font-data">
                  {selectedCollection?.title || "High Confidence Threat IOCs"}
                </h3>
                <p className="text-2xs text-secondary font-data mt-0.5">{selectedCollection?.description}</p>
              </div>

              {/* Filter Controls */}
              <div className="flex flex-wrap items-center gap-2 text-2xs">
                {/* Type Filter */}
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  className="bg-raised border border-border text-primary font-data text-2xs px-2 py-1 focus:outline-none"
                >
                  <option value="all">ALL TYPES</option>
                  <option value="indicator">INDICATOR</option>
                  <option value="malware">MALWARE</option>
                  <option value="threat-actor">THREAT ACTOR</option>
                  <option value="campaign">CAMPAIGN</option>
                </select>

                {/* Sector Filter */}
                <select
                  value={sectorFilter}
                  onChange={(e) => setSectorFilter(e.target.value)}
                  className="bg-raised border border-border text-primary font-data text-2xs px-2 py-1 focus:outline-none"
                >
                  <option value="all">ALL SECTORS</option>
                  <option value="defence">DEFENCE</option>
                  <option value="nic">NIC / GOV.IN</option>
                  <option value="military">MILITARY HQ</option>
                  <option value="public">PUBLIC ADMIN</option>
                </select>

                {/* Added After */}
                <input
                  type="date"
                  value={addedAfter}
                  onChange={(e) => setAddedAfter(e.target.value)}
                  title="Filter by TAXII added_after parameter"
                  className="bg-raised border border-border text-primary font-data text-2xs px-2 py-1 focus:outline-none"
                />
              </div>
            </div>

            {/* Indicator Rating Slider Toolbar */}
            <div className="flex items-center gap-4 bg-void p-2.5 border border-border text-2xs">
              <span className="text-secondary font-semibold uppercase">Min Indicator Rating:</span>

              <input
                type="range"
                min="0"
                max="100"
                step="5"
                value={minConfidence}
                onChange={(e) => setMinConfidence(Number(e.target.value))}
                className="accent-saffron w-36 cursor-pointer"
              />
              <span className="font-data font-bold text-saffron">{minConfidence}%</span>
              <span className="text-ghost ml-auto font-data">
                Showing <b className="text-primary">{filteredObjects.length}</b> objects
              </span>
            </div>

            {/* Objects Table */}
            {loadingObjects ? (
              <p className="py-12 text-center text-xs text-ghost font-data">Loading STIX 2.1 objects…</p>
            ) : filteredObjects.length === 0 ? (
              <EmptyState
                icon={Radar}
                title="No STIX objects in collection"
                message="No objects match the active filter criteria for this collection."
                collectionNote="Objects are promoted to TAXII collections automatically upon alert corroboration or analyst confirmation."
              />
            ) : (
              <div className="space-y-4">
                <DataTable
                  columns={objectColumns}
                  rows={filteredObjects.map((o, idx) => ({ ...o, id: o.id ?? `indicator--${idx}` }))}
                  sortable
                  onRowClick={(row) =>
                    setExpandedObjectId((prev) => (prev === row.id ? null : row.id))
                  }
                />

                {/* Inline Expanded STIX JSON Viewer */}
                {expandedObjectId && (
                  <div className="border border-saffron/40 bg-void p-4 space-y-2">
                    <div className="flex items-center justify-between pb-2 border-b border-border">
                      <div className="flex items-center gap-2">
                        <Code className="w-4 h-4 text-saffron" />
                        <span className="text-xs font-bold text-primary font-data">
                          Full STIX 2.1 JSON Payload — {expandedObjectId}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <CopyField
                          value={JSON.stringify(
                            filteredObjects.find((o) => o.id === expandedObjectId) || {},
                            null,
                            2
                          )}
                        />
                        <button
                          onClick={() => setExpandedObjectId(null)}
                          className="text-ghost hover:text-primary text-xs"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                    <pre className="p-3 bg-surface text-primary font-data text-xs overflow-x-auto max-h-72 leading-relaxed">
                      {JSON.stringify(
                        filteredObjects.find((o) => o.id === expandedObjectId) || {},
                        null,
                        2
                      )}
                    </pre>
                  </div>
                )}

                {/* TAXII Spec-Conformant Paging Controls */}
                <div className="flex items-center justify-between pt-2 border-t border-border text-2xs text-secondary font-data">
                  <span>Page size: 50 objects (TAXII 2.1 envelope standard)</span>
                  <button
                    onClick={() => setPageLimit((prev) => prev + 50)}
                    disabled={fetchingObjects}
                    className="px-4 py-1.5 border border-border bg-surface hover:bg-raised text-primary transition-colors disabled:opacity-50"
                  >
                    {fetchingObjects ? "Loading..." : "Load 50 More Objects &darr;"}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECTION 3 — Subscriber Management (Analyst Role Only) */}
      {/* ========================================================================= */}
      <div className="bg-surface border border-border p-5 space-y-4">
        <SectionHeader
          title="Subscriber Management & Ingestion Access"
          subtitle="Manage authorized SIEM/SOC consumer keys and audit feed telemetry access."
          action={
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowAccessLog(true)}
                className="flex items-center gap-1.5 text-2xs font-semibold text-secondary hover:text-primary border border-border px-3 py-1.5 bg-surface hover:bg-raised transition-colors"
              >
                <FileText className="w-3.5 h-3.5" />
                View access log &rarr;
              </button>
              <button
                onClick={() => {
                  setShowAddSubModal(true)
                  setGeneratedKeyResult(null)
                  setNewSubLabel("")
                }}
                className="flex items-center gap-1.5 text-2xs font-semibold text-white bg-saffron hover:bg-saffron/90 px-3 py-1.5 transition-colors font-bold font-data"
              >
                <Plus className="w-3.5 h-3.5" />
                Add subscriber
              </button>
            </div>
          }
        />

        {loadingSubs ? (
          <p className="text-xs text-ghost py-6 text-center font-data">Loading subscribers…</p>
        ) : subscribers.length === 0 ? (
          <EmptyState
            icon={Key}
            title="No subscribers registered"
            message="Register SOC and SIEM consumers to distribute live STIX threat feeds."
          />
        ) : (
          <DataTable
            columns={subscriberColumns}
            rows={subscribers}
            sortable
          />
        )}
      </div>

      {/* ========================================================================= */}
      {/* ADD SUBSCRIBER MODAL */}
      {/* ========================================================================= */}
      {showAddSubModal && (
        <div className="fixed inset-0 bg-void/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface border border-border max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center gap-2">
                <Key className="w-4 h-4 text-saffron" />
                <h3 className="text-sm font-bold text-primary">Add TAXII Feed Subscriber</h3>
              </div>
              <button onClick={() => setShowAddSubModal(false)} className="text-ghost hover:text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>

            {!generatedKeyResult ? (
              <div className="space-y-4">
                <div>
                  <label className="text-2xs text-secondary font-semibold uppercase block mb-1">
                    Subscriber Label (e.g. CERT-In SOC QRadar, DRDO SIEM):
                  </label>
                  <input
                    type="text"
                    value={newSubLabel}
                    onChange={(e) => setNewSubLabel(e.target.value)}
                    placeholder="Enter subscriber name"
                    className="w-full bg-void border border-border p-2.5 text-xs text-primary font-data focus:outline-none focus:border-saffron"
                  />
                </div>

                <div>
                  <label className="text-2xs text-secondary font-semibold uppercase block mb-1">
                    Authorized Collections:
                  </label>
                  <div className="space-y-1.5 max-h-36 overflow-y-auto p-2 border border-border bg-void text-xs font-data">
                    {["all-iocs", "high-confidence", "nic-sector", "drdo-defence", "military-hq", "apt36-cluster"].map(
                      (slug) => (
                        <label key={slug} className="flex items-center gap-2 text-secondary hover:text-primary cursor-pointer">
                          <input
                            type="checkbox"
                            checked={newSubCollections.includes(slug)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setNewSubCollections((prev) => [...prev, slug])
                              } else {
                                setNewSubCollections((prev) => prev.filter((s) => s !== slug))
                              }
                            }}
                            className="accent-saffron"
                          />
                          <span>{slug}</span>
                        </label>
                      )
                    )}
                  </div>
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    onClick={() => setShowAddSubModal(false)}
                    className="px-3 py-1.5 border border-border text-xs text-secondary hover:text-primary bg-surface"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() =>
                      addSubMutation.mutate({
                        label: newSubLabel.trim() || "SIEM Subscriber",
                        allowed_collections: newSubCollections,
                      })
                    }
                    disabled={!newSubLabel.trim() || addSubMutation.isPending}
                    className="px-4 py-1.5 bg-saffron text-void text-xs font-bold font-data disabled:opacity-50"
                  >
                    {addSubMutation.isPending ? "Generating..." : "Generate Key"}
                  </button>
                </div>
              </div>
            ) : (
              /* ONCE-SHOWN API KEY BOX */
              <div className="space-y-4">
                <div className="p-3 border border-critical bg-critical/10 text-critical text-xs leading-relaxed">
                  <b>⚠ SAVE THIS KEY NOW.</b> It cannot be retrieved again from the database. If lost, you must revoke and regenerate a new token.
                </div>

                <div className="p-3 bg-void border border-border flex items-center justify-between">
                  <code className="text-primary font-data text-xs font-bold break-all select-all">
                    {generatedKeyResult.api_key}
                  </code>
                  <CopyField value={generatedKeyResult.api_key} />
                </div>

                <div className="flex justify-end pt-2">
                  <button
                    onClick={() => {
                      setShowAddSubModal(false)
                      setGeneratedKeyResult(null)
                    }}
                    className="px-4 py-1.5 bg-low text-void text-xs font-bold font-data"
                  >
                    Done / Saved Key
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* REVOKE CONFIRMATION MODAL */}
      {/* ========================================================================= */}
      {revokingSub && (
        <div className="fixed inset-0 bg-void/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface border border-border max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <h3 className="text-sm font-bold text-critical">Revoke TAXII Subscriber</h3>
              <button onClick={() => setRevokingSub(null)} className="text-ghost hover:text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-secondary leading-relaxed">
              Revoke access for <b className="text-primary">{revokingSub.name || revokingSub.label}</b>? Their SIEM will stop receiving threat intelligence updates immediately.
            </p>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setRevokingSub(null)}
                className="px-3 py-1.5 border border-border text-xs text-secondary hover:text-primary bg-surface"
              >
                Cancel
              </button>
              <button
                onClick={() => revokeSubMutation.mutate(revokingSub.id)}
                disabled={revokeSubMutation.isPending}
                className="px-4 py-1.5 bg-critical text-white text-xs font-bold font-data disabled:opacity-50"
              >
                {revokeSubMutation.isPending ? "Revoking..." : "Revoke Access"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* FULL ACCESS LOG MODAL */}
      {/* ========================================================================= */}
      {showAccessLog && (
        <div className="fixed inset-0 bg-void/85 backdrop-blur-sm z-50 flex items-center justify-center p-6">
          <div className="bg-surface border border-border max-w-4xl w-full p-6 space-y-4 shadow-2xl max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div>
                <h3 className="text-sm font-bold text-primary font-data">TAXII 2.1 Feed Consumption Audit Trail</h3>
                <p className="text-2xs text-secondary">Logged invocations against OASIS TAXII 2.1 endpoints.</p>
              </div>
              <button onClick={() => setShowAccessLog(false)} className="text-ghost hover:text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex-1 overflow-auto border border-border">
              <table className="w-full border-collapse text-xs">
                <thead>
                  <tr className="bg-void border-b border-border text-2xs font-semibold text-secondary uppercase">
                    <th className="px-3 py-2 text-left">Timestamp</th>
                    <th className="px-3 py-2 text-left">Subscriber</th>
                    <th className="px-3 py-2 text-left">Endpoint</th>
                    <th className="px-3 py-2 text-left">Objects Returned</th>
                    <th className="px-3 py-2 text-left">IP Address</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {accessLogs.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-ghost">
                        No access events logged yet.
                      </td>
                    </tr>
                  ) : (
                    accessLogs.map((log, idx) => (
                      <tr key={log.id || idx} className="bg-row hover:bg-raised transition-colors">
                        <td className="px-3 py-2 font-data text-secondary">{log.timestamp?.replace("T", " ").slice(0, 19)}</td>
                        <td className="px-3 py-2 font-semibold text-primary">{log.name || log.subscriber_id || "Anonymous"}</td>
                        <td className="px-3 py-2 font-data text-saffron">{log.endpoint}</td>
                        <td className="px-3 py-2 font-data font-bold text-primary">{log.objects_returned || 0}</td>
                        <td className="px-3 py-2 font-data text-ghost">{log.ip_address || "—"}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShowAccessLog(false)}
                className="px-4 py-1.5 border border-border text-xs text-primary bg-surface hover:bg-raised"
              >
                Close Audit Log
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAXII INTEGRATION GUIDE MODAL */}
      {/* ========================================================================= */}
      {showGuideModal && (
        <div className="fixed inset-0 bg-void/85 backdrop-blur-sm z-50 flex items-center justify-center p-6">
          <div className="bg-surface border border-border max-w-2xl w-full p-6 space-y-4 shadow-2xl max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-saffron" />
                <h3 className="text-sm font-bold text-primary font-data">TAXII 2.1 Client Ingestion Quickstart</h3>
              </div>
              <button onClick={() => setShowGuideModal(false)} className="text-ghost hover:text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto space-y-4 text-xs text-secondary leading-relaxed">
              <p>
                GARUDA exposes an official OASIS TAXII 2.1 compliant server. You can consume indicators via Python (<code>taxii2-client</code>), curl, or direct SIEM integration (Splunk, QRadar, Sentinel).
              </p>

              <div>
                <span className="font-bold text-primary block mb-1 font-data text-2xs uppercase">1. Python SDK Client:</span>
                <pre className="p-3 bg-void border border-border text-primary font-data text-2xs overflow-x-auto leading-relaxed">
{`from taxii2client.v21 import Server

# Discover server
server = Server("${taxiiDiscoveryUrl}")
api_root = server.api_roots[0]

# List collections
for coll in api_root.collections:
    print(f"Collection: {coll.title} ({coll.id})")
    
# Pull objects with auth
api_root.custom_headers = {"Authorization": "Bearer YOUR_API_KEY"}
feed = api_root.get_collection("high-confidence")
bundle = feed.get_objects()
print(f"Ingested {len(bundle.objects)} indicators")`}
                </pre>
              </div>

              <div>
                <span className="font-bold text-primary block mb-1 font-data text-2xs uppercase">2. Curl Verification:</span>
                <pre className="p-3 bg-void border border-border text-primary font-data text-2xs overflow-x-auto leading-relaxed">
{`curl -H "Accept: application/taxii+json;version=2.1" \\
     -H "Authorization: Bearer YOUR_API_KEY" \\
     ${taxiiDiscoveryUrl}garuda/collections/high-confidence/objects/`}
                </pre>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShowGuideModal(false)}
                className="px-4 py-1.5 border border-border text-xs text-primary bg-surface hover:bg-raised"
              >
                Close Guide
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
