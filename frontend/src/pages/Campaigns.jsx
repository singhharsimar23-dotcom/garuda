import React, { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { Layers, Calendar, Server, ChevronDown, ChevronUp, ShieldAlert } from "lucide-react"
import { Link } from "react-router-dom"

import { getCampaigns, getCampaign } from "../lib/api"

export default function Campaigns() {
  const [expandedCluster, setExpandedCluster] = useState(null)

  const { data, isLoading } = useQuery({
    queryKey: ["campaigns"],
    queryFn: getCampaigns,
    refetchInterval: 30000,
  })

  const { data: detailData } = useQuery({
    queryKey: ["campaignDetail", expandedCluster],
    queryFn: () => getCampaign(expandedCluster),
    enabled: !!expandedCluster,
  })

  const campaigns = data?.campaigns || []

  return (
    <div className="space-y-6 pb-10">
      {/* Top Header */}
      <div className="bg-navy-900/60 border border-navy-800 p-5 rounded-2xl shadow-xl">
        <h2 className="text-xl font-black tracking-tight text-white flex items-center gap-2">
          <Layers className="w-5 h-5 text-blue-400" />
          <span>APT36 Attack Campaigns (DBSCAN Clusters)</span>
        </h2>
        <p className="text-xs text-gray-400 mt-1">
          Algorithmic infrastructure clustering grouping multi-domain staging operations with attack window forecasts
        </p>
      </div>

      {isLoading ? (
        <div className="flex justify-center items-center py-20 text-gray-400 space-x-2">
          <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
          <span>Clustering correlated campaign vectors...</span>
        </div>
      ) : campaigns.length === 0 ? (
        <div className="p-8 text-center bg-navy-900 border border-navy-800 rounded-2xl text-gray-500 italic">
          No multi-domain campaign clusters detected in current evaluation window.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {campaigns.map((camp) => {
            const isExpanded = expandedCluster === camp.cluster_id
            const windowDays = camp.estimated_attack_window_days || 15

            return (
              <div
                key={camp.cluster_id}
                className="bg-navy-900 border border-navy-700/80 rounded-2xl p-5 shadow-xl transition-all duration-200 hover:border-navy-600 flex flex-col justify-between"
              >
                <div>
                  <div className="flex justify-between items-start mb-3">
                    <div>
                      <span className="text-[10px] font-mono uppercase text-gray-500 font-bold">Campaign Identifier</span>
                      <h3 className="text-lg font-black font-mono text-cyan-400">{camp.cluster_id}</h3>
                    </div>
                    <span className="px-2.5 py-1 rounded-lg bg-orange-500/20 text-orange-400 border border-orange-500/40 text-xs font-mono font-bold flex items-center gap-1">
                      <Calendar className="w-3.5 h-3.5" />
                      <span>~{windowDays} Days Window</span>
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs text-gray-300 mb-4 bg-navy-950/70 p-3 rounded-xl border border-navy-800">
                    <div>
                      <span className="text-gray-500 block text-[10px] uppercase font-bold">Staged Domains</span>
                      <span className="font-mono text-white font-bold">{camp.domain_count} Nodes</span>
                    </div>
                    <div>
                      <span className="text-gray-500 block text-[10px] uppercase font-bold">Infrastructure ASN</span>
                      <span className="font-mono text-cyan-300">AS{camp.hosting_asn || "Multiple"}</span>
                    </div>
                    <div className="col-span-2 mt-1">
                      <span className="text-gray-500 block text-[10px] uppercase font-bold">Targeted Sectors</span>
                      <span className="text-gray-200">
                        {camp.sectors && camp.sectors.length > 0 ? camp.sectors.join(", ") : "National Defence / MoD"}
                      </span>
                    </div>
                  </div>
                </div>

                <div>
                  <button
                    onClick={() => setExpandedCluster(isExpanded ? null : camp.cluster_id)}
                    className="w-full py-2 px-3 rounded-xl bg-navy-800 hover:bg-navy-700 text-gray-200 text-xs font-semibold flex items-center justify-center space-x-2 transition-colors border border-navy-700"
                  >
                    <span>{isExpanded ? "Collapse Campaign Domains" : "Inspect Member Domains"}</span>
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>

                  {/* Expanded Domain Members */}
                  {isExpanded && (
                    <div className="mt-3 pt-3 border-t border-navy-800 space-y-2 animate-fade-in">
                      <p className="text-[11px] font-bold text-gray-400 uppercase tracking-wider">Associated Domain Indicators</p>
                      {detailData?.member_alerts && detailData.member_alerts.length > 0 ? (
                        <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                          {detailData.member_alerts.map((alert) => (
                            <Link
                              key={alert.id}
                              to={`/alerts/${alert.id}`}
                              className="flex justify-between items-center bg-navy-950 p-2 rounded-lg border border-navy-800 hover:border-cyan-500/50 text-xs transition-colors"
                            >
                              <div className="flex items-center space-x-2 font-mono">
                                <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                                <span className="text-gray-200">{alert.domain}</span>
                              </div>
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 font-mono">
                                {alert.score}/100
                              </span>
                            </Link>
                          ))}
                        </div>
                      ) : camp.domains && camp.domains.length > 0 ? (
                        <div className="space-y-1 text-xs font-mono text-gray-300">
                          {camp.domains.map((d) => (
                            <div key={d} className="bg-navy-950 p-2 rounded-lg border border-navy-800">
                              {d}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-gray-500 italic">No direct member domain list available.</p>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
