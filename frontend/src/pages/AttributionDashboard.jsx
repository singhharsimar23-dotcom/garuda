import React, { useEffect, useRef, useState } from "react"
import * as d3 from "d3"
import { Fingerprint, Network } from "lucide-react"

import SectionHeader from "../components/ui/SectionHeader"
import EmptyState from "../components/ui/EmptyState"
import ConfidencePill from "../components/ui/ConfidencePill"

const NODE_SHAPES = {
  IP: "circle",
  EMAIL: "square",
  SSH_KEY: "diamond",
  GIT: "triangle",
}

function confidenceColor(conf) {
  const n = Number(conf) || 0
  if (n >= 0.85) return "#FF3B30"
  if (n >= 0.6) return "#FF9500"
  return "#FFD60A"
}

function drawShape(g, type, color) {
  const t = (type || "IP").toUpperCase()
  if (t === "EMAIL" || NODE_SHAPES[t] === "square") {
    g.append("rect").attr("x", -8).attr("y", -8).attr("width", 16).attr("height", 16).attr("fill", color).attr("stroke", "#060B14").attr("stroke-width", 1.5)
  } else if (t === "SSH_KEY" || NODE_SHAPES[t] === "diamond") {
    g.append("path").attr("d", "M0,-10 L10,0 L0,10 L-10,0 Z").attr("fill", color).attr("stroke", "#060B14").attr("stroke-width", 1.5)
  } else if (t === "GIT" || NODE_SHAPES[t] === "triangle") {
    g.append("path").attr("d", "M0,-10 L10,8 L-10,8 Z").attr("fill", color).attr("stroke", "#060B14").attr("stroke-width", 1.5)
  } else {
    g.append("circle").attr("r", 10).attr("fill", color).attr("stroke", "#060B14").attr("stroke-width", 1.5)
  }
}

export default function AttributionDashboard() {
  const svgRef = useRef(null)
  const [graph, setGraph] = useState({ nodes: [], links: [] })
  const [clusters, setClusters] = useState([])
  const [clusterFilter, setClusterFilter] = useState("")
  const [loading, setLoading] = useState(true)
  const [hoveredEdge, setHoveredEdge] = useState(null)

  useEffect(() => {
    const url = clusterFilter
      ? `/api/attribution/graph?cluster=${encodeURIComponent(clusterFilter)}`
      : "/api/attribution/graph"
    setLoading(true)
    fetch(url)
      .then((r) => (r.ok ? r.json() : { nodes: [], links: [] }))
      .then((data) => {
        setGraph({
          nodes: Array.isArray(data.nodes) ? data.nodes : [],
          links: Array.isArray(data.links) ? data.links : [],
        })
        setClusters(Array.isArray(data.clusters) ? data.clusters : [])
      })
      .catch(() => {
        setGraph({ nodes: [], links: [] })
        setClusters([])
      })
      .finally(() => setLoading(false))
  }, [clusterFilter])

  useEffect(() => {
    if (!svgRef.current || graph.nodes.length === 0) return

    const width = svgRef.current.clientWidth || 800
    const height = 500

    d3.select(svgRef.current).selectAll("*").remove()

    const svg = d3.select(svgRef.current).attr("viewBox", [0, 0, width, height])
    const g = svg.append("g")

    svg.call(
      d3.zoom().scaleExtent([0.2, 4]).on("zoom", (event) => {
        g.attr("transform", event.transform)
      })
    )

    const nodes = graph.nodes.map((n) => ({ ...n }))
    const links = graph.links.map((l) => ({ ...l }))

    const simulation = d3
      .forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d) => d.id).distance(100))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(30))

    const link = g
      .append("g")
      .selectAll("line")
      .data(links)
      .enter()
      .append("line")
      .attr("stroke", "#1E3349")
      .attr("stroke-width", 1.5)
      .on("mouseenter", (_, d) => setHoveredEdge(d.edge_type || "related"))
      .on("mouseleave", () => setHoveredEdge(null))

    const node = g
      .append("g")
      .selectAll("g")
      .data(nodes)
      .enter()
      .append("g")
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

    node.each(function (d) {
      drawShape(d3.select(this), d.type, confidenceColor(d.confidence))
    })

    node
      .append("text")
      .attr("dy", 22)
      .attr("text-anchor", "middle")
      .attr("font-size", "9px")
      .attr("fill", "#6B85A8")
      .attr("font-family", "JetBrains Mono, monospace")
      .text((d) => {
        const label = d.label || d.id || ""
        return label.length > 18 ? `${label.slice(0, 16)}…` : label
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
  }, [graph])

  return (
    <div className="py-6 px-6 space-y-4 min-h-screen">
      <SectionHeader
        title="Persona Attribution Graph"
        subtitle="Force-directed graph of operator persona nodes — IP, email, SSH key, and git identity correlations."
        action={
          <div className="flex items-center gap-2">
            <label className="text-2xs text-secondary uppercase">Cluster</label>
            <select
              value={clusterFilter}
              onChange={(e) => setClusterFilter(e.target.value)}
              className="bg-void border border-border text-xs font-data text-primary px-2 py-1 focus:outline-none focus:border-saffron"
            >
              <option value="">All clusters</option>
              {clusters.map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
            <a
              href="/attribution/review"
              className="text-2xs font-data text-info hover:underline ml-2"
            >
              Cluster Review →
            </a>
          </div>
        }
      />

      <div className="flex items-center gap-4 text-2xs text-secondary font-data">
        {Object.entries(NODE_SHAPES).map(([type, shape]) => (
          <span key={type} className="flex items-center gap-1">
            <span className="text-primary">{type}</span>= {shape}
          </span>
        ))}
        <ConfidencePill confidence={75} methodology="Node colour: high=critical, medium=high, low=medium — from persona confidence score" />
      </div>

      {hoveredEdge && (
        <p className="text-2xs font-data text-saffron bg-void border border-border px-2 py-1 inline-block">
          Edge: {hoveredEdge}
        </p>
      )}

      <div className="bg-surface border border-border h-[520px] relative">
        {loading ? (
          <p className="text-xs text-ghost text-center py-20">Loading persona graph…</p>
        ) : graph.nodes.length === 0 ? (
          <EmptyState
            icon={Network}
            title="No persona nodes indexed"
            message="Persona nodes are populated from canary fires, malware hunt observations, and analyst enrichment."
          />
        ) : (
          <svg ref={svgRef} className="w-full h-full" data-testid="persona-graph" />
        )}
      </div>
    </div>
  )
}
