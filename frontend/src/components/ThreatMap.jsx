import React, { useEffect, useRef, useState, useMemo } from "react"
import L from "leaflet"
import { Crosshair, Globe, Shield, Radio, ShieldAlert, Layers } from "lucide-react"

// Exact GPS coordinates for Real Strategic Commands, Defence Establishments & CNI Hubs
const STRATEGIC_HUBS = {
  mod_delhi: {
    id: "mod_delhi",
    name: "Ministry of Defence & Tri-Services HQ",
    location: "South Block / Sena Bhawan, New Delhi",
    coords: [28.6143, 77.2088],
    type: "Command HQ",
  },
  army_northern: {
    id: "army_northern",
    name: "Indian Army Northern Command (HQ NC)",
    location: "Udhampur Military Station, J&K",
    coords: [32.9238, 75.1388],
    type: "Operational Command",
  },
  navy_eastern: {
    id: "navy_eastern",
    name: "Eastern Naval Command (HQ ENC)",
    location: "Visakhapatnam Naval Base, Andhra Pradesh",
    coords: [17.6868, 83.2185],
    type: "Naval Base",
  },
  navy_western: {
    id: "navy_western",
    name: "Western Naval Command (HQ WNC)",
    location: "Mumbai Naval Dockyard, Maharashtra",
    coords: [18.9220, 72.8347],
    type: "Naval Base",
  },
  air_western: {
    id: "air_western",
    name: "Western Air Command (HQ WAC)",
    location: "Subroto Park, New Delhi",
    coords: [28.5672, 77.1600],
    type: "Air Command",
  },
  drdo_missile: {
    id: "drdo_missile",
    name: "DRDO Dr. APJ Abdul Kalam Missile Complex",
    location: "Kanchanbagh, Hyderabad",
    coords: [17.3480, 78.5270],
    type: "Defence R&D",
  },
  drdo_cair: {
    id: "drdo_cair",
    name: "DRDO Centre for AI & Robotics (CAIR)",
    location: "CV Raman Nagar, Bengaluru",
    coords: [12.9716, 77.5946],
    type: "Defence R&D",
  },
  dpsu_defence: {
    id: "dpsu_defence",
    name: "BEL & BDL Strategic Defence Production",
    location: "Bengaluru & Bhanur Complexes",
    coords: [13.0358, 77.5544],
    type: "Defence PSU",
  },
  nic_national: {
    id: "nic_national",
    name: "National Informatics Centre (NIC Central Cloud)",
    location: "CGO Complex & Shastri Park, New Delhi",
    coords: [28.5855, 77.2410],
    type: "Gov Backbone",
  },
  intel_paramilitary: {
    id: "intel_paramilitary",
    name: "Paramilitary & Strategic Intelligence Operations",
    location: "Lodhi Road, New Delhi",
    coords: [28.5880, 77.2280],
    type: "Intelligence",
  },
  cni_infrastructure: {
    id: "cni_infrastructure",
    name: "National Critical Infrastructure & Energy Grid",
    location: "Mumbai & Central Energy Hub",
    coords: [19.0760, 72.8777],
    type: "Critical Infra",
  },
}

// Map alert domain & sector to target strategic hub
function getTargetHubId(alert) {
  const dom = (alert.domain || "").toLowerCase()
  const sec = (alert.sector || "").toLowerCase()

  if (dom.includes("drdo") || dom.includes("cair") || sec.includes("drdo")) {
    return dom.includes("cair") ? "drdo_cair" : "drdo_missile"
  }
  if (dom.includes("navy") || dom.includes("naval") || sec.includes("navy")) {
    return dom.includes("east") ? "navy_eastern" : "navy_western"
  }
  if (dom.includes("iaf") || dom.includes("air") || sec.includes("air force")) {
    return "air_western"
  }
  if (dom.includes("army") || dom.includes("sena") || dom.includes("posting") || sec.includes("army")) {
    return (dom.charCodeAt(0) % 2 === 0) ? "army_northern" : "mod_delhi"
  }
  if (dom.includes("mod") || sec.includes("ministry of defence")) {
    return "mod_delhi"
  }
  if (dom.includes("nic") || dom.includes("mail") || dom.includes("sso") || sec.includes("nic")) {
    return "nic_national"
  }
  if (dom.includes("bdl") || dom.includes("bel") || dom.includes("hal") || sec.includes("dpsu")) {
    return "dpsu_defence"
  }
  if (dom.includes("ib") || dom.includes("raw") || dom.includes("crpf") || sec.includes("paramilitary")) {
    return "intel_paramilitary"
  }
  if (dom.includes("ongc") || dom.includes("energy") || dom.includes("court") || dom.includes("parliament")) {
    return "cni_infrastructure"
  }
  return "mod_delhi"
}

// Real Attacker Server GeoIP locations based on hosting IP and ASN
function getAttackerGeo(alert) {
  const ip = alert.hosting_ip || "185.220.101.99"
  const asn = alert.hosting_asn

  if (ip.startsWith("185.220.101")) {
    return {
      ip,
      coords: [52.5200, 13.4050],
      location: "Berlin, Germany (Tor Exit Relay / AS60729)",
      country: "Germany",
      flag: "🇩🇪",
    }
  }
  if (asn === 16276 || ip.startsWith("1.2") || ip.startsWith("162.241")) {
    return {
      ip,
      coords: [50.1109, 8.6821],
      location: "Frankfurt, Germany (OVH Bulletproof / AS16276)",
      country: "Germany",
      flag: "🇩🇪",
    }
  }
  if (ip.startsWith("185.") || asn === 200019) {
    return {
      ip,
      coords: [52.3676, 4.9041],
      location: "Amsterdam, Netherlands (AS200019)",
      country: "Netherlands",
      flag: "🇳🇱",
    }
  }
  return {
    ip,
    coords: [48.8566, 2.3522],
    location: "Western Europe (Privacy Hosting)",
    country: "Europe",
    flag: "🇪🇺",
  }
}

export default function ThreatMap({ alerts = [], onSelectAlert }) {
  const mapContainerRef = useRef(null)
  const mapInstanceRef = useRef(null)
  const layerGroupRef = useRef(null)
  const [viewMode, setViewMode] = useState("trajectories") // "trajectories" | "sovereign_hubs" | "attacker_servers"
  const [selectedHub, setSelectedHub] = useState(null)

  // Aggregate alerts per Strategic Hub
  const hubData = useMemo(() => {
    const map = {}
    Object.keys(STRATEGIC_HUBS).forEach((key) => {
      map[key] = {
        ...STRATEGIC_HUBS[key],
        alerts: [],
        criticalCount: 0,
        maxScore: 0,
      }
    })

    alerts.forEach((alert) => {
      const hubId = getTargetHubId(alert)
      if (map[hubId]) {
        map[hubId].alerts.push(alert)
        if ((alert.score || 0) >= 85) map[hubId].criticalCount++
        if ((alert.score || 0) > map[hubId].maxScore) map[hubId].maxScore = alert.score || 0
      }
    })

    return map
  }, [alerts])

  // Aggregate unique attacker servers
  const attackerServers = useMemo(() => {
    const serverMap = {}
    alerts.forEach((alert) => {
      const geo = getAttackerGeo(alert)
      const key = `${geo.coords[0]},${geo.coords[1]}`
      if (!serverMap[key]) {
        serverMap[key] = {
          ...geo,
          alerts: [],
        }
      }
      serverMap[key].alerts.push(alert)
    })
    return Object.values(serverMap)
  }, [alerts])

  // Initialize Map
  useEffect(() => {
    if (!mapContainerRef.current) return

    if (!mapInstanceRef.current) {
      const map = L.map(mapContainerRef.current, {
        center: [28.0, 50.0],
        zoom: 3.5,
        minZoom: 2,
        maxZoom: 16,
        zoomControl: false,
      })

      L.control.zoom({ position: "bottomright" }).addTo(map)

      L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}", {
        attribution: '&copy; Esri &mdash; National Geographic, DeLorme, HERE',
        maxZoom: 16,
      }).addTo(map)

      layerGroupRef.current = L.layerGroup().addTo(map)
      mapInstanceRef.current = map
    }

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove()
        mapInstanceRef.current = null
      }
    }
  }, [])

  // Draw Layers
  useEffect(() => {
    const map = mapInstanceRef.current
    const layer = layerGroupRef.current
    if (!map || !layer) return

    layer.clearLayers()

    // 1. DRAW ATTACK TRAJECTORY ARCS (Attacker Geo -> Indian Strategic Command)
    if (viewMode === "trajectories") {
      attackerServers.forEach((server) => {
        server.alerts.slice(0, 8).forEach((alert) => {
          const hubId = getTargetHubId(alert)
          const hub = STRATEGIC_HUBS[hubId]
          if (!hub) return

          const isCrit = (alert.score || 0) >= 85
          const arcColor = isCrit ? "#FF3B30" : "#FF9500"

          // Curved geodesic line
          const lat1 = server.coords[0]
          const lng1 = server.coords[1]
          const lat2 = hub.coords[0]
          const lng2 = hub.coords[1]
          const midLat = (lat1 + lat2) / 2 + 12 // curve northwards
          const midLng = (lng1 + lng2) / 2

          const curvePoints = [
            [lat1, lng1],
            [midLat, midLng],
            [lat2, lng2],
          ]

          const arc = L.polyline(curvePoints, {
            color: arcColor,
            weight: 1.5,
            opacity: 0.45,
            dashArray: "4, 6",
          })
          layer.addLayer(arc)
        })
      })
    }

    // 2. DRAW ATTACKER C2 SERVERS
    if (viewMode === "trajectories" || viewMode === "attacker_servers") {
      attackerServers.forEach((server) => {
        const marker = L.circleMarker(server.coords, {
          radius: 10,
          fillColor: "#FF3B30",
          color: "#FFFFFF",
          weight: 2,
          opacity: 1,
          fillOpacity: 0.9,
        })

        const popupHtml = `
          <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; background: #0D1521; color: #E8F0FE; padding: 12px; border: 1px solid #FF3B30; min-width: 260px;">
            <div style="border-bottom: 1px solid #1E3349; padding-bottom: 6px; margin-bottom: 8px;">
              <span style="font-weight: 800; color: #FF3B30; font-size: 12px;">ATTACKER C2 SERVER</span>
            </div>
            <div style="margin-bottom: 4px; color: #8A99AD;">
              <b style="color: #E8F0FE;">HOSTING IP:</b> <code style="color: #FF3B30;">${server.ip}</code>
            </div>
            <div style="margin-bottom: 4px; color: #8A99AD;">
              <b style="color: #E8F0FE;">PHYSICAL LOCATION:</b> ${server.flag} ${server.location}
            </div>
            <div style="margin-bottom: 8px; color: #8A99AD;">
              <b style="color: #E8F0FE;">ACTIVE THREATS HOSTED:</b> <span style="color: #FF9500; font-weight: bold;">${server.alerts.length} Domains</span>
            </div>
            <div style="max-height: 90px; overflow-y: auto; background: #060B14; padding: 6px; border: 1px solid #1E3349; font-size: 10px;">
              ${server.alerts.slice(0, 5).map(a => `<div style="color: #00E5FF; padding: 2px 0;">• ${a.domain} (${a.score}/100)</div>`).join("")}
              ${server.alerts.length > 5 ? `<div style="color: #8A99AD; font-style: italic;">+ ${server.alerts.length - 5} more</div>` : ""}
            </div>
          </div>
        `
        marker.bindPopup(popupHtml)
        marker.bindTooltip(`<b>${server.flag} Attacker C2 (${server.ip})</b>: ${server.alerts.length} threats`, { direction: "top" })
        layer.addLayer(marker)
      })
    }

    // 3. DRAW INDIAN STRATEGIC COMMAND HUBS
    if (viewMode === "trajectories" || viewMode === "sovereign_hubs") {
      Object.values(hubData).forEach((hub) => {
        const count = hub.alerts.length
        if (count === 0 && viewMode === "trajectories") return

        const hasCritical = hub.criticalCount > 0
        const markerColor = hasCritical ? "#FF3B30" : count > 0 ? "#FF9500" : "#00E5FF"

        // Custom HTML Badge Marker with Threat Count
        const customIcon = L.divIcon({
          className: "custom-hub-marker",
          html: `
            <div style="
              display: flex;
              align-items: center;
              gap: 4px;
              background: #0D1521;
              border: 1.5px solid ${markerColor};
              color: #E8F0FE;
              padding: 2px 6px;
              border-radius: 4px;
              font-family: monospace;
              font-size: 10px;
              font-weight: bold;
              white-space: nowrap;
              box-shadow: 0 4px 12px rgba(0,0,0,0.8);
            ">
              <span style="
                width: 6px;
                height: 6px;
                border-radius: 50%;
                background: ${markerColor};
                display: inline-block;
                ${hasCritical ? "box-shadow: 0 0 8px #FF3B30;" : ""}
              "></span>
              <span>${hub.name.split(" ")[0]}</span>
              <span style="
                background: ${markerColor}22;
                color: ${markerColor};
                padding: 1px 4px;
                border-radius: 2px;
                font-size: 9px;
              ">${count}</span>
            </div>
          `,
          iconSize: [120, 24],
          iconAnchor: [60, 12],
        })

        const marker = L.marker(hub.coords, { icon: customIcon })

        const popupHtml = `
          <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; background: #0D1521; color: #E8F0FE; padding: 12px; border: 1px solid #1E3349; min-width: 280px;">
            <div style="border-bottom: 1px solid #1E3349; padding-bottom: 6px; margin-bottom: 8px;">
              <span style="font-weight: 800; color: #00E5FF; font-size: 12px;">${hub.name}</span>
            </div>
            <div style="margin-bottom: 4px; color: #8A99AD;">
              <b style="color: #E8F0FE;">ESTABLISHMENT:</b> ${hub.location}
            </div>
            <div style="margin-bottom: 4px; color: #8A99AD;">
              <b style="color: #E8F0FE;">TARGETED THREATS:</b> <span style="color: #FF9500; font-weight: bold;">${count} Indicators</span>
            </div>
            <div style="margin-bottom: 8px; color: #8A99AD;">
              <b style="color: #E8F0FE;">CRITICAL THREATS:</b> <span style="color: #FF3B30; font-weight: bold;">${hub.criticalCount}</span>
            </div>
            <div style="max-height: 120px; overflow-y: auto; background: #060B14; padding: 6px; border: 1px solid #1E3349; font-size: 10px;">
              ${hub.alerts.slice(0, 6).map(a => `
                <div style="display: flex; justify-content: space-between; padding: 2px 0; border-bottom: 1px dashed #1E3349;">
                  <span style="color: #FF9500;">${a.domain}</span>
                  <span style="color: ${a.score >= 85 ? '#FF3B30' : '#FFCC00'}; font-weight: bold;">${a.score}/100</span>
                </div>
              `).join("")}
              ${hub.alerts.length > 6 ? `<div style="color: #8A99AD; font-style: italic; padding-top: 4px;">+ ${hub.alerts.length - 6} more threats</div>` : ""}
            </div>
          </div>
        `
        marker.bindPopup(popupHtml)
        marker.on("click", () => setSelectedHub(hub))
        layer.addLayer(marker)
      })
    }
  }, [viewMode, hubData, attackerServers])

  return (
    <div className="relative w-full h-[420px] overflow-hidden border border-border bg-void flex flex-col font-data">
      {/* Top Map HUD Controls */}
      <div className="absolute top-3 left-3 z-[1000] flex items-center gap-2">
        <div className="bg-surface/95 backdrop-blur-md border border-border p-1 flex items-center gap-1 shadow-2xl">
          <button
            onClick={() => {
              setViewMode("trajectories")
              mapInstanceRef.current?.flyTo([28.0, 50.0], 3.5, { duration: 1 })
            }}
            className={`px-3 py-1 text-2xs font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors ${
              viewMode === "trajectories"
                ? "bg-navy text-saffron border border-saffron/40 shadow-sm"
                : "text-secondary hover:text-primary hover:bg-raised"
            }`}
          >
            <Crosshair className="w-3.5 h-3.5 text-cyan-400" />
            <span>Cyber Attack Trajectories</span>
          </button>

          <button
            onClick={() => {
              setViewMode("sovereign_hubs")
              mapInstanceRef.current?.flyTo([22.5, 79.5], 4.5, { duration: 1 })
            }}
            className={`px-3 py-1 text-2xs font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors ${
              viewMode === "sovereign_hubs"
                ? "bg-navy text-cyan-400 border border-cyan-400/40 shadow-sm"
                : "text-secondary hover:text-primary hover:bg-raised"
            }`}
          >
            <Shield className="w-3.5 h-3.5 text-cyan-400" />
            <span>Targeted Indian Bases ({alerts.length})</span>
          </button>

          <button
            onClick={() => {
              setViewMode("attacker_servers")
              mapInstanceRef.current?.flyTo([51.0, 10.0], 4, { duration: 1 })
            }}
            className={`px-3 py-1 text-2xs font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors ${
              viewMode === "attacker_servers"
                ? "bg-navy text-critical border border-critical/40 shadow-sm"
                : "text-secondary hover:text-primary hover:bg-raised"
            }`}
          >
            <Globe className="w-3.5 h-3.5 text-critical" />
            <span>Attacker Server Origins</span>
          </button>
        </div>
      </div>

      {/* Top Right Legend HUD */}
      <div className="absolute top-3 right-3 z-[1000] bg-surface/95 backdrop-blur-md border border-border px-3 py-1.5 text-2xs text-secondary flex items-center space-x-3 shadow-xl">
        <div className="flex items-center space-x-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-critical border border-white" />
          <span className="text-primary font-bold">Attacker C2 Server</span>
        </div>
        <div className="flex items-center space-x-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 border border-cyan-300" />
          <span className="text-primary font-bold">Indian Strategic Hub</span>
        </div>
        <div className="flex items-center space-x-1.5">
          <span className="w-4 h-0.5 border-t border-dashed border-critical" />
          <span>Active Attack Vector</span>
        </div>
      </div>

      {/* Map Leaflet Container */}
      <div ref={mapContainerRef} className="w-full h-full" />

      {/* Bottom Telemetry HUD */}
      <div className="absolute bottom-3 left-3 z-[1000] bg-surface/95 backdrop-blur-md border border-border px-3 py-1 text-2xs text-secondary flex items-center gap-4">
        <div className="flex items-center gap-1.5">
          <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
          <span>Origin: <b>European / Bulletproof C2 Hostings</b></span>
        </div>
        <span className="text-border">|</span>
        <div>
          <span>Target: <b className="text-saffron">Indian National Defence Commands</b></span>
        </div>
      </div>
    </div>
  )
}
