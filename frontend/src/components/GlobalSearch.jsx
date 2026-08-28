import React, { useState, useEffect, useMemo, useRef } from "react"
import { useNavigate } from "react-router-dom"
import {
  Search,
  ShieldAlert,
  Radar,
  Server,
  Fingerprint,
  ExternalLink,
  Command,
  X,
} from "lucide-react"

export default function GlobalSearch() {
  const [isOpen, setIsOpen] = useState(false)
  const [query, setQuery] = useState("")
  const inputRef = useRef(null)
  const navigate = useNavigate()

  // Listen for Cmd+K / Ctrl+K
  useEffect(() => {
    function handleKeyDown(e) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault()
        setIsOpen((prev) => !prev)
      } else if (e.key === "Escape") {
        setIsOpen(false)
      }
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [])

  // Auto-focus input on open
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50)
    } else {
      setQuery("")
    }
  }, [isOpen])

  // Sample indexed entities for quick navigation
  const searchIndex = useMemo(() => {
    return [
      // Domains & Alerts
      { type: "Alert", title: "drdo-gov-in.nic-portal.org", desc: "Critical Score: 92/100 • APT36 Impersonation", link: "/alerts", domain: "drdo-gov-in.nic-portal.org" },
      { type: "Alert", title: "mod-defence-gov.in", desc: "High Score: 88/100 • Ministry of Defence", link: "/alerts", domain: "mod-defence-gov.in" },
      { type: "Alert", title: "nic-secure-vpn.org", desc: "Score: 78/100 • Sovereign Gov Portal", link: "/alerts", domain: "nic-secure-vpn.org" },

      // STIX Indicators
      { type: "STIX Indicator", title: "indicator--d18f2301-44bb-4e92-911a-0b92134901", desc: "STIX 2.1 Pattern: [domain-name:value = 'drdo-gov-in.nic-portal.org']", link: "/intelligence" },
      { type: "STIX Indicator", title: "indicator--a9411032-11ee-4819-bf91-9921448102", desc: "STIX 2.1 Pattern: [ipv4-addr:value = '45.142.214.88']", link: "/intelligence" },

      // EASM IPs & CIDRs
      { type: "Attack Surface IP", title: "59.160.0.44", desc: "DRDO Hyderabad Netblock • Exposed Port 443 (FortiOS)", link: "/surface" },
      { type: "Attack Surface IP", title: "164.100.12.18", desc: "National Informatics Centre • Open Port 80 (HTTP)", link: "/surface" },

      // CVEs
      { type: "CVE Vulnerability", title: "CVE-2024-21762", desc: "FortiOS SSL-VPN Remote Code Execution • CISA KEV Listed", external: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2024-21762" },
      { type: "CVE Vulnerability", title: "CVE-2023-3519", desc: "Citrix ADC Unauthenticated Remote Code Execution", external: "https://nvd.nist.gov/vuln/detail/CVE-2023-3519" },

      // Operator Clusters
      { type: "Operator Cluster", title: "cluster-a-nic-mod", desc: "APT36 Working Group • 14 Campaigns Corroborated", link: "/attribution" },
      { type: "Operator Cluster", title: "cluster-b-defence-porkbun", desc: "Adversary Sub-cluster • NameSilo Registrar Affinity", link: "/attribution" },

      // Monitored Orgs
      { type: "Monitored Org", title: "DRDO (Defence Research and Development Organisation)", desc: "18 Monitored CIDR Ranges • APNIC WHOIS Verified", link: "/surface" },
      { type: "Monitored Org", title: "NIC (National Informatics Centre)", desc: "32 Monitored Netblocks • IRINN Registered", link: "/surface" },
    ]
  }, [])

  // Filtered results
  const results = useMemo(() => {
    if (!query.trim()) return []
    const q = query.toLowerCase()
    return searchIndex.filter((item) =>
      item.title.toLowerCase().includes(q) ||
      item.desc.toLowerCase().includes(q) ||
      item.type.toLowerCase().includes(q)
    )
  }, [query, searchIndex])

  // Group results by type
  const groupedResults = useMemo(() => {
    const map = {}
    for (const r of results) {
      if (!map[r.type]) map[r.type] = []
      map[r.type].push(r)
    }
    return map
  }, [results])

  const handleSelect = (item) => {
    setIsOpen(false)
    if (item.external) {
      window.open(item.external, "_blank", "noopener,noreferrer")
    } else if (item.link) {
      navigate(item.link)
    }
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-void/85 backdrop-blur-sm z-50 flex items-start justify-center pt-20 p-4">
      <div className="bg-surface border border-border max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col">
        {/* Search Input Bar */}
        <div className="p-3 bg-void border-b border-border flex items-center gap-3">
          <Search className="w-4 h-4 text-saffron shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search domains, IPs, CVEs, STIX IDs, clusters, organisations... (Cmd+K)"
            className="w-full bg-transparent text-primary text-xs font-data focus:outline-none placeholder:text-ghost"
          />
          {query && (
            <button onClick={() => setQuery("")} className="text-ghost hover:text-primary">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
          <span className="text-2xs font-data bg-surface border border-border text-secondary px-1.5 py-0.5">
            ESC
          </span>
        </div>

        {/* Results Container */}
        <div className="max-h-96 overflow-y-auto p-3 space-y-4">
          {!query.trim() ? (
            <div className="py-8 text-center text-ghost text-xs font-data space-y-1">
              <p>Type to search across the entire sovereign telemetry database.</p>
              <p className="text-2xs text-ghost">Matches domains, IP ranges, CVE matches, STIX 2.1 IDs, and operator clusters.</p>
            </div>
          ) : results.length === 0 ? (
            <div className="py-8 text-center text-ghost text-xs font-data">
              No entities found matching "{query}".
            </div>
          ) : (
            Object.entries(groupedResults).map(([type, items]) => (
              <div key={type} className="space-y-1.5">
                <div className="text-2xs font-bold uppercase tracking-widest text-secondary font-data px-1">
                  {type} ({items.length})
                </div>
                <div className="divide-y divide-border border border-border bg-void">
                  {items.map((item, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleSelect(item)}
                      className="w-full p-2.5 text-left hover:bg-raised transition-colors flex items-center justify-between group"
                    >
                      <div className="space-y-0.5 max-w-lg">
                        <div className="font-data font-bold text-xs text-primary group-hover:text-saffron transition-colors">
                          {item.title}
                        </div>
                        <div className="text-2xs text-secondary truncate">{item.desc}</div>
                      </div>
                      {item.external ? (
                        <ExternalLink className="w-3.5 h-3.5 text-ghost group-hover:text-primary shrink-0" />
                      ) : (
                        <span className="text-2xs font-data text-ghost group-hover:text-primary shrink-0">
                          Jump &rarr;
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
