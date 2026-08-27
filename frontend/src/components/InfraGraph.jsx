import React, { useEffect, useRef, useState } from "react"
import * as d3 from "d3"

const NODE_COLORS = {
  domain: "#3b82f6",
  ip: "#ef4444",
  certificate: "#10b981",
  cert: "#10b981",
  nameserver: "#eab308",
  ns: "#eab308",
  registrar: "#a855f7",
}

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
      .force("link", d3.forceLink(edges).id((d) => d.id).distance(100))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(30))

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
      .attr("r", (d) => (d.type === "domain" ? 14 : 9))
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
    <div className="relative w-full h-full">
      {selectedNode && (
        <div className="absolute top-2 left-2 z-10 bg-navy-950/90 border border-navy-700 rounded-lg px-3 py-2 text-[11px] text-gray-200 shadow-xl max-w-xs">
          <p className="font-bold text-cyan-400 uppercase text-[10px]">{selectedNode.type}</p>
          <p className="font-mono break-all">{selectedNode.label || selectedNode.id}</p>
          {selectedNode.asn && <p className="text-gray-400">ASN: {selectedNode.asn}</p>}
          {selectedNode.country && <p className="text-gray-400">Country: {selectedNode.country}</p>}
        </div>
      )}
      <svg ref={svgRef} className="w-full h-full" />
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
