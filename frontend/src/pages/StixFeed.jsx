import React from "react"
import { useQuery } from "@tanstack/react-query"
import { toast } from "react-hot-toast"
import { Share2, Copy, Download, RefreshCw } from "lucide-react"

import { getStixFeed } from "../lib/api"

export default function StixFeed() {
  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["stixFeed"],
    queryFn: getStixFeed,
    staleTime: 300000,
  })

  const rawJson = data ? JSON.stringify(data, null, 2) : ""

  const copyJson = () => {
    navigator.clipboard.writeText(rawJson)
    toast.success("STIX 2.1 JSON Bundle copied to clipboard!")
  }

  const downloadJson = () => {
    const blob = new Blob([rawJson], { type: "application/json" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `GARUDA_STIX2_Feed_${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
    toast.success("STIX 2.1 Feed downloaded!")
  }

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-navy-900/60 border border-navy-800 p-5 rounded-2xl shadow-xl">
        <div>
          <h2 className="text-xl font-black tracking-tight text-white flex items-center gap-2">
            <Share2 className="w-5 h-5 text-cyan-400" />
            <span>STIX 2.1 Cyber Threat Intelligence Sharing Feed</span>
          </h2>
          <p className="text-xs text-gray-400 mt-1">
            Standardized OASIS STIX 2.1 JSON Bundle of confirmed sovereign defense indicators cached at edge
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => refetch()}
            className="px-3 py-1.5 rounded-lg bg-navy-800 hover:bg-navy-700 text-gray-200 text-xs font-semibold flex items-center space-x-1.5 border border-navy-700"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
          <button
            onClick={copyJson}
            disabled={!data}
            className="px-3 py-1.5 rounded-lg bg-navy-800 hover:bg-navy-700 text-cyan-300 text-xs font-semibold flex items-center space-x-1.5 border border-navy-700 disabled:opacity-50"
          >
            <Copy className="w-3.5 h-3.5" />
            <span>Copy Bundle</span>
          </button>
          <button
            onClick={downloadJson}
            disabled={!data}
            className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center space-x-1.5 shadow-lg shadow-cyan-600/30 disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download JSON</span>
          </button>
        </div>
      </div>

      {/* JSON Viewer Card */}
      <div className="bg-navy-900 border border-navy-700/80 rounded-2xl p-5 shadow-2xl space-y-3">
        <div className="flex justify-between items-center text-xs text-gray-400 font-mono">
          <span>OASIS STIX 2.1 Compliant Format</span>
          <span>Feed Endpoint: <code>/api/stix/feed</code> (TTL: 300s)</span>
        </div>

        {isLoading ? (
          <div className="py-24 text-center text-gray-500 flex justify-center items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
            <span>Serializing STIX 2.1 threat objects...</span>
          </div>
        ) : (
          <pre className="w-full bg-navy-950 border border-navy-800 rounded-xl p-4 font-mono text-[11px] text-cyan-300 overflow-x-auto max-h-[580px] leading-relaxed">
            {rawJson}
          </pre>
        )}
      </div>
    </div>
  )
}
