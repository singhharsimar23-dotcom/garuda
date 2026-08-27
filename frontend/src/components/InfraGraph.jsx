import React, { useEffect, useRef, useState } from "react"
import * as d3 from "d3"
import { HelpCircle, Info, Layers, Network, Shield, X } from "lucide-react"

const NODE_COLORS = {
  domain: "#3b82f6",       // Blue (Primary or related domain)
  ip: "#ef4444",           // Red (Hosting IP address)
  certificate: "#10b981",  // Emerald (SSL Certificate SAN)
  cert: "#10b981",
  nameserver: "#eab308",   // Amber (Authoritative DNS Nameserver)
  ns: "#eab308",
  registrant_cluster: "#a855f7", // Purple (Registrar/temporal cluster hash)
  registrar: "#a855f7",
}

const LEGEND_ITEMS = [
  { type: "domain", label: "Target / Sibling Domain", color: "#3b82f6" },
  { type: "ip", label: "Hosting Server IP", color: "#ef4444" },
  { type: "nameserver", label: "Shared Nameserver", color: "#eab308" },
  { type: "certificate", label: "SSL SAN Certificate", color: "#10b981" },
  { type: "registrant_cluster", label: "Registrant Cluster", color: "#a855f7" },
]

class InfraGraphErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false }
  }
  static getDerivedStateFromError() {
    return { hasError: true }
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="flex items-center justify-center h-full text-xs text-gray-500 italic p-4 text-center">
          Infrastructure graph unavailable for this alert.
        </div>
      )
    }
    return this.props.children
  }
}

function InfraGraphInner({ graphData, onNodeClick }) {
  const svgRef = useRef(null)
  const [selectedNode, setSelectedNode] = useState(null)
  const [showGuide, setShowGuide] = useState(false)

  // Normalize backend edge format {s, t} → D3 format {source, target}
  const rawNodes = graphData?.nodes ?? []
  const rawEdges = graphData?.edges ?? graphData?.links ?? []

  const nodes = rawNodes.map((n) => ({
    ...n,
    label: n.label || n.domain || n.id,
  }))

  const edges = rawEdges.map((e) => ({
    source: e.source ?? e.s,
    target: e.target ?? e.t,
    type: e.type,
  }))

  useEffect(() => {
    if (!svgRef.current || !nodes || nodes.length === 0) return

    const container = svgRef.current
    const width = container.clientWidth || 800
    const height = container.clientHeight || 450

    d3.select(container).selectAll("*").remove()

    const svg = d3
      .select(container)
      .attr("viewBox", [0, 0, width, height])
      .attr("width", "100%")
      .attr("height", "100%")

    const g = svg.append("g")

    const zoom = d3
      .zoom()
      .scaleExtent([0.2, 5])
      .on("zoom", (event) => {
        g.attr("transform", event.transform)
      })

    svg.call(zoom)

    const simulation = d3
      .forceSimulation(nodes)
      .force("link", d3.forceLink(edges).id((d) => d.id).distance(110))
      .force("charge", d3.forceManyBody().strength(-350))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(35))

    const link = g
      .append("g")
      .selectAll("line")
      .data(edges)
      .enter()
      .append("line")
      .attr("stroke", "#334155")
      .attr("stroke-width", 1.5)
      .attr("stroke-dasharray", "4,2")

    const node = g
      .append("g")
      .selectAll("g")
      .data(nodes)
      .enter()
      .append("g")
      .attr("cursor", "pointer")
      .call(
        d3.drag()
          .on("start", (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart()
            d.fx = d.x
            d.fy = d.y
          })
          .on("drag", (event, d) => {
            d.fx = event.x
            d.fy = event.y
          })
          .on("end", (event, d) => {
            if (!event.active) simulation.alphaTarget(0)
            d.fx = null
            d.fy = null
          })
      )
      .on("click", (event, d) => {
        setSelectedNode(d)
        if (onNodeClick) onNodeClick(d)
      })

    node
      .append("circle")
      .attr("r", (d) => (d.type === "domain" ? 14 : 10))
      .attr("fill", (d) => NODE_COLORS[d.type] || "#64748b")
      .attr("stroke", "#0f172a")
      .attr("stroke-width", 2)
      .attr("filter", (d) => (d.type === "domain" ? "url(#glow)" : null))

    const defs = svg.append("defs")
    const filter = defs.append("filter").attr("id", "glow")
    filter.append("feGaussianBlur").attr("stdDeviation", "3").attr("result", "coloredBlur")
    const feMerge = filter.append("feMerge")
    feMerge.append("feMergeNode").attr("in", "coloredBlur")
    feMerge.append("feMergeNode").attr("in", "SourceGraphic")

    node
      .append("text")
      .attr("dy", 24)
      .attr("text-anchor", "middle")
      .attr("font-size", "9px")
      .attr("fill", "#94a3b8")
      .attr("font-weight", "600")
      .text((d) => {
        const label = d.label || d.id || ""
        return label.length > 20 ? label.slice(0, 18) + "…" : label
      })

    simulation.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y)

      node.attr("transform", (d) => `translate(${d.x},${d.y})`)
    })

    return () => {
      simulation.stop()
    }
  }, [nodes, edges])

  if (!nodes || nodes.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-xs text-gray-500 italic p-4 text-center">
        No infrastructure graph data available. Graph builds after PDNS enrichment.
      </div>
    )
  }

  return (
    <div className="relative w-full h-full min-h-[420px] bg-navy-950/60 rounded-xl overflow-hidden border border-navy-800 flex flex-col">
      {/* Top Bar Controls & Legend */}
      <div className="absolute top-3 right-3 z-10 flex items-center gap-2">
        <button
          onClick={() => setShowGuide(!showGuide)}
          className="px-2.5 py-1 rounded-lg bg-navy-900/90 hover:bg-navy-800 border border-cyan-500/30 text-cyan-300 text-xs font-semibold flex items-center gap-1.5 shadow-lg backdrop-blur transition-colors"
        >
          <HelpCircle className="w-3.5 h-3.5 text-cyan-400" />
          <span>{showGuide ? "Hide Guide" : "How to Read"}</span>
        </button>
      </div>

      {/* Selected Node Inspector Badge */}
      {selectedNode && (
        <div className="absolute top-3 left-3 z-10 bg-navy-900/95 border border-cyan-500/40 rounded-xl p-3 text-[11px] text-gray-200 shadow-2xl max-w-xs backdrop-blur space-y-1">
          <div className="flex justify-between items-center pb-1 border-b border-navy-700">
            <span
              className="px-2 py-0.5 rounded text-[9px] font-black uppercase tracking-wider"
              style={{
                backgroundColor: `${NODE_COLORS[selectedNode.type] || "#64748b"}22`,
                color: NODE_COLORS[selectedNode.type] || "#94a3b8",
                border: `1px solid ${NODE_COLORS[selectedNode.type] || "#64748b"}44`,
              }}
            >
              {selectedNode.type}
            </span>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-gray-400 hover:text-white"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          <p className="font-mono text-cyan-300 font-bold break-all pt-1">
            {selectedNode.label || selectedNode.id}
          </p>
          {selectedNode.score !== undefined && (
            <p className="text-gray-400">Threat Score: <b className="text-white">{selectedNode.score}/100</b></p>
          )}
          {selectedNode.asn && <p className="text-gray-400">ASN: <b className="text-white">{selectedNode.asn}</b></p>}
          {selectedNode.country && <p className="text-gray-400">Country: <b className="text-white">{selectedNode.country}</b></p>}
        </div>
      )}

      {/* Interactive Guide Drawer / Panel */}
      {showGuide && (
        <div className="absolute inset-x-3 top-14 z-20 bg-navy-950/95 border border-cyan-500/40 rounded-xl p-4 text-xs text-gray-200 shadow-2xl backdrop-blur max-h-[340px] overflow-y-auto space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-navy-800">
            <div className="flex items-center gap-2 text-cyan-300 font-bold">
              <Network className="w-4 h-4" />
              <span>4-Pivot Infrastructure Correlation Guide</span>
            </div>
            <button
              onClick={() => setShowGuide(false)}
              className="text-gray-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <p className="text-[11px] text-gray-400 leading-relaxed">
            Attackers rarely register only one domain. This graph maps the surrounding infrastructure footprint using four correlation pivots:
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1">
            <div className="p-2.5 rounded-lg bg-navy-900/90 border border-blue-500/20 space-y-1">
              <p className="font-bold text-blue-400 flex items-center gap-1.5 text-[11px]">
                <span className="w-2 h-2 rounded-full bg-blue-400" />
                1. SSL SAN Pivot (crt.sh)
              </p>
              <p className="text-[10px] text-gray-400">
                Discovers sibling domains sharing the same multi-domain SSL/TLS certificate.
              </p>
            </div>

            <div className="p-2.5 rounded-lg bg-navy-900/90 border border-red-500/20 space-y-1">
              <p className="font-bold text-red-400 flex items-center gap-1.5 text-[11px]">
                <span className="w-2 h-2 rounded-full bg-red-400" />
                2. Reverse IP Pivot
              </p>
              <p className="text-[10px] text-gray-400">
                Finds other attacker C2 or decoy domains hosted on the exact same server IP address.
              </p>
            </div>

            <div className="p-2.5 rounded-lg bg-navy-900/90 border border-amber-500/20 space-y-1">
              <p className="font-bold text-amber-400 flex items-center gap-1.5 text-[11px]">
                <span className="w-2 h-2 rounded-full bg-amber-400" />
                3. Passive DNS (NS) Pivot
              </p>
              <p className="text-[10px] text-gray-400">
                Identifies co-managed attack domains utilizing identical bulletproof authoritative nameservers.
              </p>
            </div>

            <div className="p-2.5 rounded-lg bg-navy-900/90 border border-purple-500/20 space-y-1">
              <p className="font-bold text-purple-400 flex items-center gap-1.5 text-[11px]">
                <span className="w-2 h-2 rounded-full bg-purple-400" />
                4. Registrant Temporal Hash
              </p>
              <p className="text-[10px] text-gray-400">
                Groups domains batch-registered through the same registrar within the same operational time window.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* SVG Canvas */}
      <div className="flex-1 w-full h-full min-h-[380px]">
        <svg ref={svgRef} className="w-full h-full" />
      </div>

      {/* Bottom Floating Legend */}
      <div className="p-2 bg-navy-950/80 border-t border-navy-900 flex flex-wrap items-center justify-center gap-3 text-[10px] text-gray-400">
        {LEGEND_ITEMS.map((item) => (
          <div key={item.type} className="flex items-center gap-1.5">
            <span
              className="w-2.5 h-2.5 rounded-full"
              style={{ backgroundColor: item.color }}
            />
            <span>{item.label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function InfraGraph(props) {
  return (
    <InfraGraphErrorBoundary>
      <InfraGraphInner {...props} />
    </InfraGraphErrorBoundary>
  )
}
