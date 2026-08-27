import React, { useEffect, useRef, useState } from "react"
import * as d3 from "d3"

const NODE_COLORS = {
  domain: "#3b82f6",    // Blue
  ip: "#ef4444",        // Red
  certificate: "#10b981", // Green
  cert: "#10b981",
  nameserver: "#eab308", // Yellow
  ns: "#eab308",
  registrar: "#a855f7", // Purple
}

export default function InfraGraph({ graphData, onNodeClick }) {
  const svgRef = useRef(null)
  const [selectedNode, setSelectedNode] = useState(null)

  useEffect(() => {
    if (!svgRef.current || !graphData || !graphData.nodes || graphData.nodes.length === 0) return

    const container = svgRef.current
    const width = container.clientWidth || 800
    const height = container.clientHeight || 450

    // Clear previous elements
    d3.select(container).selectAll("*").remove()

    const svg = d3
      .select(container)
      .attr("viewBox", [0, 0, width, height])
      .attr("width", "100%")
      .attr("height", "100%")

    // Add zoom & pan container
    const g = svg.append("g")

    const zoom = d3
      .zoom()
      .scaleExtent([0.2, 5])
      .on("zoom", (event) => {
        g.attr("transform", event.transform)
      })

    svg.call(zoom)

    // Deep copy data to prevent in-place D3 mutation bugs
    const nodes = graphData.nodes.map((d) => ({ ...d }))
    const edges = (graphData.edges || []).map((d) => ({ ...d }))

    // Arrow markers for directed relationships
    svg
      .append("defs")
      .append("marker")
      .attr("id", "arrow")
      .attr("viewBox", "0 -5 10 10")
      .attr("refX", 22)
      .attr("refY", 0)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M0,-5L10,0L0,5")
      .attr("fill", "#475569")

    // Force simulation setup
    const simulation = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3
          .forceLink(edges)
          .id((d) => d.id)
          .distance(90)
      )
      .force("charge", d3.forceManyBody().strength(-240))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(32))

    // Draw edge links
    const link = g
      .append("g")
      .attr("stroke", "#334155")
      .attr("stroke-opacity", 0.7)
      .selectAll("line")
      .data(edges)
      .join("line")
      .attr("stroke-width", (d) => Math.sqrt(d.weight || 1) * 1.5)
      .attr("marker-end", "url(#arrow)")

    // Draw edge labels
    const edgeLabels = g
      .append("g")
      .selectAll("text")
      .data(edges)
      .join("text")
      .attr("font-size", 9)
      .attr("fill", "#94a3b8")
      .attr("text-anchor", "middle")
      .text((d) => d.label || d.relation || "")

    // Draw node circles
    const node = g
      .append("g")
      .selectAll("g")
      .data(nodes)
      .join("g")
      .call(
        d3
          .drag()
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

    // Node circular shape
    node
      .append("circle")
      .attr("r", (d) => (d.type === "domain" ? 18 : 13))
      .attr("fill", (d) => NODE_COLORS[d.type?.toLowerCase()] || "#64748b")
      .attr("stroke", "#0f172a")
      .attr("stroke-width", 2)
      .attr("cursor", "pointer")
      .attr("class", "transition-all hover:opacity-80")

    // Node labels
    node
      .append("text")
      .attr("y", (d) => (d.type === "domain" ? 28 : 22))
      .attr("text-anchor", "middle")
      .attr("fill", "#e2e8f0")
      .attr("font-size", 10)
      .attr("font-weight", 600)
      .text((d) => {
        const name = d.label || d.domain || d.ip || d.id || ""
        return name.length > 20 ? name.slice(0, 17) + "..." : name
      })

    // Simulation tick callback
    simulation.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y)

      edgeLabels
        .attr("x", (d) => (d.source.x + d.target.x) / 2)
        .attr("y", (d) => (d.source.y + d.target.y) / 2 - 3)

      node.attr("transform", (d) => `translate(${d.x},${d.y})`)
    })

    // Cleanup simulation on unmount
    return () => {
      simulation.stop()
    }
  }, [graphData, onNodeClick])

  return (
    <div className="relative w-full h-full min-h-[420px] bg-navy-950 rounded-xl border border-navy-700/70 overflow-hidden shadow-2xl flex flex-col">
      {/* Legend */}
      <div className="absolute top-3 left-3 z-10 bg-navy-900/80 backdrop-blur-md px-3 py-2 rounded-lg border border-navy-700 text-xs text-gray-300 flex flex-wrap gap-3">
        <div className="flex items-center space-x-1.5">
          <span className="w-3 h-3 rounded-full bg-blue-500" />
          <span>Domain</span>
        </div>
        <div className="flex items-center space-x-1.5">
          <span className="w-3 h-3 rounded-full bg-red-500" />
          <span>IP Host</span>
        </div>
        <div className="flex items-center space-x-1.5">
          <span className="w-3 h-3 rounded-full bg-green-500" />
          <span>SSL Cert</span>
        </div>
        <div className="flex items-center space-x-1.5">
          <span className="w-3 h-3 rounded-full bg-yellow-500" />
          <span>Nameserver</span>
        </div>
      </div>

      {/* SVG Canvas */}
      <svg ref={svgRef} className="w-full h-full min-h-[420px]" />

      {/* Node inspect drawer */}
      {selectedNode && (
        <div className="absolute bottom-3 right-3 z-10 bg-navy-900/90 backdrop-blur-md p-3 rounded-xl border border-navy-600 text-xs text-gray-200 max-w-xs shadow-2xl animate-fade-in">
          <div className="flex justify-between items-center mb-1">
            <span className="font-bold text-sm text-cyan-400 capitalize">{selectedNode.type} Node</span>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-gray-400 hover:text-white font-bold ml-2"
            >
              &times;
            </button>
          </div>
          <div className="space-y-1 text-[11px] text-gray-300">
            <div><b className="text-gray-400">Value:</b> <span className="font-mono">{selectedNode.label || selectedNode.domain || selectedNode.id}</span></div>
            {selectedNode.score !== undefined && <div><b className="text-gray-400">Score:</b> <span className="text-red-400 font-bold">{selectedNode.score}/100</span></div>}
            {selectedNode.asn && <div><b className="text-gray-400">ASN:</b> AS{selectedNode.asn}</div>}
            {selectedNode.country && <div><b className="text-gray-400">Country:</b> {selectedNode.country}</div>}
          </div>
        </div>
      )}
    </div>
  )
}
