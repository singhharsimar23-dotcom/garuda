import React, { useEffect, useRef, useState } from "react"
import L from "leaflet"
import "leaflet/dist/leaflet.css"
import { Globe, Radio, Target } from "lucide-react"

import SectionHeader from "../components/ui/SectionHeader"
import EmptyState from "../components/ui/EmptyState"
import CopyField from "../components/ui/CopyField"

const COUNTRY_COORDS = {
  china: [35.0, 105.0],
  cn: [35.0, 105.0],
  india: [22.0, 79.0],
  in: [22.0, 79.0],
  "united states": [39.0, -98.0],
  us: [39.0, -98.0],
  russia: [61.0, 90.0],
  ru: [61.0, 90.0],
  netherlands: [52.2, 5.3],
  nl: [52.2, 5.3],
  germany: [51.0, 10.0],
  de: [51.0, 10.0],
  "hong kong": [22.3, 114.2],
  hk: [22.3, 114.2],
}

function coordsForNode(node) {
  const country = (node.country || "").toLowerCase().trim()
  if (COUNTRY_COORDS[country]) {
    const [lat, lng] = COUNTRY_COORDS[country]
    const jitter = ((node.ip || "").charCodeAt(0) || 0) % 10
    return [lat + jitter * 0.3, lng + jitter * 0.3]
  }
  const ip = node.ip || "0.0.0.0"
  const parts = ip.split(".").map(Number)
  const lat = 10 + (parts[0] || 0) * 0.5
  const lng = -30 + (parts[1] || 0) * 1.2
  return [lat, lng]
}

function markerColor(node) {
  const score = Number(node.orb_score) || 0
  if (node.targeting_indian_defence) return "#FF3B30"
  if (score >= 80) return "#FF3B30"
  if (score >= 60) return "#FF9500"
  return "#6B85A8"
}

export default function OrbTracker() {
  const mapRef = useRef(null)
  const mapInstanceRef = useRef(null)
  const layerRef = useRef(null)
  const [nodes, setNodes] = useState([])
  const [stats, setStats] = useState({ total: 0, probable: 0, confirmed: 0, targeting_india: 0 })
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState(null)

  useEffect(() => {
    fetch("/api/orb/nodes")
      .then((r) => (r.ok ? r.json() : { nodes: [], stats: {} }))
      .then((data) => {
        setNodes(Array.isArray(data.nodes) ? data.nodes : [])
        setStats(data.stats || { total: 0, probable: 0, confirmed: 0, targeting_india: 0 })
      })
      .catch(() => {
        setNodes([])
        setStats({ total: 0, probable: 0, confirmed: 0, targeting_india: 0 })
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (!mapRef.current) return
    if (!mapInstanceRef.current) {
      const map = L.map(mapRef.current, {
        center: [20, 80],
        zoom: 4,
        zoomControl: true,
      })
      L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}", {
        attribution: "© Esri, DeLorme, NAVTEQ",
        maxZoom: 16,
      }).addTo(map)
      layerRef.current = L.layerGroup().addTo(map)
      mapInstanceRef.current = map
      setTimeout(() => map.invalidateSize(), 200)
    }
    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove()
        mapInstanceRef.current = null
        layerRef.current = null
      }
    }
  }, [])

  useEffect(() => {
    const layer = layerRef.current
    if (!layer || !mapInstanceRef.current) return
    layer.clearLayers()

    nodes.forEach((node) => {
      const coords = coordsForNode(node)
      const color = markerColor(node)
      const pulsing = node.targeting_indian_defence

      const marker = L.circleMarker(coords, {
        radius: pulsing ? 10 : 7,
        fillColor: color,
        color: "#ffffff",
        weight: pulsing ? 2 : 1,
        fillOpacity: 0.85,
        className: pulsing ? "orb-pulse-marker" : "",
      })

      marker.on("click", () => setSelected(node))
      marker.bindTooltip(
        `<b>${node.ip || "unknown"}</b><br/>${node.country || "—"} — ${node.product || "SOHO Gateway"}<br/>ORB Score: ${node.orb_score || 0}/130`,
        { className: "garuda-tooltip", direction: "top" }
      )
      layer.addLayer(marker)
    })
    setTimeout(() => mapInstanceRef.current?.invalidateSize(), 150)
  }, [nodes])

  return (
    <div className="py-6 px-6 space-y-4 min-h-screen">
      <SectionHeader
        title="ORB Network Tracker"
        subtitle="Operational Relay Box nodes — compromised SOHO routers and VPS relays observed via Shodan, BGP, and IOC correlation."
      />

      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: "Total Nodes", value: stats.total || nodes.length, icon: Globe },
          { label: "Probable", value: stats.probable, color: "text-high" },
          { label: "Confirmed", value: stats.confirmed, color: "text-critical" },
          { label: "Targeting India", value: stats.targeting_india, icon: Target, color: "text-saffron" },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-surface border border-border px-4 py-3 flex items-center justify-between">
            <div>
              <p className="text-2xs text-secondary uppercase tracking-widest">{label}</p>
              <p className={`font-data text-xl font-bold ${color || "text-primary"}`}>{value}</p>
            </div>
            {Icon && <Icon className={`w-5 h-5 ${color || "text-ghost"}`} />}
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-8 relative border border-border bg-void" style={{ height: "520px" }}>
          <div ref={mapRef} className="w-full h-full" style={{ height: "520px", width: "100%" }} data-testid="orb-map" />
          {loading && (
            <div className="absolute inset-0 bg-void/70 flex items-center justify-center pointer-events-none">
              <p className="text-xs text-ghost">Loading ORB telemetry…</p>
            </div>
          )}
          {!loading && nodes.length === 0 && (
            <div className="absolute bottom-4 left-4 right-4 bg-surface/90 border border-border p-3 text-center pointer-events-none">
              <p className="text-2xs text-secondary font-data">Weekly automated ORB sweeps active via GitHub Actions</p>
            </div>
          )}
        </div>

        <div className="lg:col-span-4 bg-surface border border-border p-4 min-h-[480px]">
          <h3 className="text-2xs font-bold text-secondary uppercase tracking-widest mb-3">Node Detail</h3>
          {!selected ? (
            <p className="text-xs text-ghost">Click a map marker to inspect node signals.</p>
          ) : (
            <div className="space-y-3 text-xs">
              <div>
                <span className="text-secondary">IP</span>
                <div className="mt-1"><CopyField value={selected.ip} /></div>
              </div>
              <div className="grid grid-cols-2 gap-2 font-data">
                <div><span className="text-secondary">ASN</span><p className="text-primary">{selected.asn ? `AS${selected.asn}` : "—"}</p></div>
                <div><span className="text-secondary">Country</span><p className="text-primary">{selected.country || "—"}</p></div>
                <div><span className="text-secondary">Product</span><p className="text-primary">{selected.product || "—"}</p></div>
                <div><span className="text-secondary">Score</span><p className="text-saffron font-bold">{selected.orb_score}/130</p></div>
              </div>
              <div>
                <span className="text-secondary">Triggered Signals</span>
                <ul className="mt-1 space-y-1">
                  {(selected.triggered_signals || []).map((s) => (
                    <li key={s} className="font-data text-2xs bg-void border border-border px-2 py-1 text-primary">{s}</li>
                  ))}
                </ul>
              </div>
              <div>
                <span className="text-secondary">Anchor ASNs (Chinese transit)</span>
                <p className="font-data text-primary mt-1">
                  {(selected.anchor_asns_found || []).map((a) => `AS${a}`).join(", ") || "—"}
                </p>
              </div>
              {selected.targeting_indian_defence && (
                <p className="text-critical font-bold text-2xs border border-critical/40 bg-critical/10 px-2 py-1">
                  TARGETING INDIAN DEFENCE PREFIX
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
