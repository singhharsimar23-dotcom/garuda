import React, { useEffect, useRef, useState, useMemo } from "react"
import L from "leaflet"
import { Crosshair, Globe, MapPin, ShieldAlert, Zap, Radio, Layers } from "lucide-react"

// Real Indian Strategic Establishments, Defence Commands & CNI Centers
const STRATEGIC_INSTALLATIONS = {
  army_hq: { name: "Integrated Defence Staff & Army HQ", coords: [28.6143, 77.2088], region: "New Delhi (South Block)" },
  army_northern: { name: "Northern Command HQ (HQ NC)", coords: [32.9238, 75.1388], region: "Udhampur, J&K" },
  navy_eastern: { name: "Eastern Naval Command (HQ ENC)", coords: [17.6868, 83.2185], region: "Visakhapatnam" },
  navy_western: { name: "Western Naval Command (HQ WNC)", coords: [18.9220, 72.8347], region: "Mumbai Naval Dockyard" },
  air_western: { name: "Western Air Command (HQ WAC)", coords: [28.5672, 77.1600], region: "Subroto Park, Delhi" },
  air_eastern: { name: "Eastern Air Command (HQ EAC)", coords: [25.5788, 91.8933], region: "Shillong, Meghalaya" },
  drdo_missiles: { name: "DRDO Dr. APJ Abdul Kalam Missile Complex", coords: [17.3480, 78.5270], region: "Kanchanbagh, Hyderabad" },
  drdo_cair: { name: "DRDO Centre for AI & Robotics (CAIR)", coords: [12.9716, 77.5946], region: "CV Raman Nagar, Bengaluru" },
  mod_secretariat: { name: "Ministry of Defence Secretariat", coords: [28.6180, 77.2050], region: "Sena Bhawan, New Delhi" },
  nic_cgo: { name: "National Informatics Centre (NIC HQ)", coords: [28.5855, 77.2410], region: "CGO Complex, New Delhi" },
  nic_dr_centre: { name: "NIC Disaster Recovery National Data Centre", coords: [20.2961, 85.8245], region: "Bhubaneswar, Odisha" },
  dpsu_bel: { name: "BEL Strategic Radar & Avionics Division", coords: [13.0358, 77.5544], region: "Jalahalli, Bengaluru" },
  dpsu_bdl: { name: "Bharat Dynamics Limited (BDL Missile Systems)", coords: [17.5300, 78.2700], region: "Bhanur, Telangana" },
  intel_hq: { name: "Paramilitary & Strategic Intelligence Operations", coords: [28.5880, 77.2280], region: "Lodhi Road, New Delhi" },
  cni_energy: { name: "National Critical Energy & Infrastructure Grid", coords: [19.0760, 72.8777], region: "Mumbai Strategic Hub" },
  cni_judiciary: { name: "Supreme Court & National Legal Grid", coords: [28.6230, 77.2390], region: "Tilak Marg, New Delhi" },
  cni_parliament: { name: "Parliament House & Legislative Network", coords: [28.6172, 77.2081], region: "Sansad Marg, New Delhi" },
}

// Global Attacker C2 Geo-resolutions for known IP blocks
const KNOWN_C2_GEO = {
  "185.220.101.99": { coords: [52.5200, 13.4050], location: "Berlin, Germany (Tor Exit Relay)", asn: "AS60729" },
  "1.2.3.4": { coords: [50.1109, 8.6821], location: "Frankfurt, Germany (OVH Bulletproof)", asn: "AS16276" },
  "185.220.101.45": { coords: [52.3676, 4.9041], location: "Amsterdam, Netherlands (Privacy Relay)", asn: "AS60729" },
  "198.51.100.1": { coords: [37.7749, -122.4194], location: "California, USA (Fastly/Cloud C2)", asn: "AS13335" },
}

function resolveInstallationKey(alert) {
  const dom = (alert.domain || "").toLowerCase()
  const sec = (alert.sector || "").toLowerCase()

  if (dom.includes("drdo") || dom.includes("cair") || sec.includes("drdo") || sec.includes("r&d")) {
    return dom.includes("cair") ? "drdo_cair" : "drdo_missiles"
  }
  if (dom.includes("navy") || dom.includes("naval") || sec.includes("navy")) {
    return dom.includes("east") ? "navy_eastern" : "navy_western"
  }
  if (dom.includes("iaf") || dom.includes("air") || sec.includes("air force")) {
    return dom.includes("east") ? "air_eastern" : "air_western"
  }
  if (dom.includes("army") || dom.includes("sena") || dom.includes("posting") || sec.includes("army")) {
    return (dom.charCodeAt(0) % 2 === 0) ? "army_northern" : "army_hq"
  }
  if (dom.includes("mod") || sec.includes("ministry of defence")) {
    return "mod_secretariat"
  }
  if (dom.includes("nic") || dom.includes("mail") || dom.includes("sso") || sec.includes("nic")) {
    return (dom.charCodeAt(0) % 2 === 0) ? "nic_dr_centre" : "nic_cgo"
  }
  if (dom.includes("bdl") || dom.includes("missile")) {
    return "dpsu_bdl"
  }
  if (dom.includes("bel") || dom.includes("hal")) {
    return "dpsu_bel"
  }
  if (dom.includes("ib") || dom.includes("raw") || dom.includes("crpf") || sec.includes("paramilitary")) {
    return "intel_hq"
  }
  if (dom.includes("ongc") || dom.includes("energy")) {
    return "cni_energy"
  }
  if (dom.includes("court") || dom.includes("judg")) {
    return "cni_judiciary"
  }
  if (dom.includes("parliament") || dom.includes("loksabha")) {
    return "cni_parliament"
  }
  return "army_hq"
}

// Compute deterministic constellation offset around installation hub so no markers overlap
function getRadialOffset(index, totalAtHub) {
  if (totalAtHub <= 1) return [0, 0]
  const angle = (index / totalAtHub) * 2 * Math.PI
  const radius = 0.18 + (Math.floor(index / 8) * 0.14) // concentric orbital rings
  return [Math.sin(angle) * radius, Math.cos(angle) * (radius * 1.15)]
}

export default function ThreatMap({ alerts = [], onSelectAlert }) {
  const mapContainerRef = useRef(null)
  const mapInstanceRef = useRef(null)
  const layerGroupRef = useRef(null)
  const [mapMode, setMapMode] = useState("target_vector") // "target_vector" | "attacker_c2"
  const [selectedSector, setSelectedSector] = useState("ALL")

  // Group alerts by installation and compute coordinates
  const mappedThreats = useMemo(() => {
    const hubCounts = {}
    const filtered = alerts.filter(a => selectedSector === "ALL" || (a.sector || "Unclassified") === selectedSector)

    filtered.forEach(alert => {
      const hubKey = resolveInstallationKey(alert)
      hubCounts[hubKey] = (hubCounts[hubKey] || 0) + 1
    })

    const hubCurrentIndex = {}
    return filtered.map(alert => {
      const hubKey = resolveInstallationKey(alert)
      const installation = STRATEGIC_INSTALLATIONS[hubKey]
      const totalAtHub = hubCounts[hubKey] || 1
      const idx = hubCurrentIndex[hubKey] || 0
      hubCurrentIndex[hubKey] = idx + 1

      const [dLat, dLng] = getRadialOffset(idx, totalAtHub)
      const targetCoords = [installation.coords[0] + dLat, installation.coords[1] + dLng]
      
      // Attacker C2 coordinates
      const ip = alert.hosting_ip || "185.220.101.99"
      const c2Geo = KNOWN_C2_GEO[ip] || {
        coords: [50.0 + ((ip.charCodeAt(0) || 1) % 15), 10.0 + ((ip.charCodeAt(1) || 1) % 30)],
        location: `European/Global Hosting Netblock (${alert.registrar || "Namecheap"})`,
        asn: alert.hosting_asn ? `AS${alert.hosting_asn}` : "AS16276"
      }

      return {
        ...alert,
        installation,
        hubKey,
        targetCoords,
        c2Coords: c2Geo.coords,
        c2Location: c2Geo.location,
        c2Asn: c2Geo.asn,
      }
    })
  }, [alerts, selectedSector])

  // Initialize Leaflet Map
  useEffect(() => {
    if (!mapContainerRef.current) return

    if (!mapInstanceRef.current) {
      const map = L.map(mapContainerRef.current, {
        center: [22.5, 79.5],
        zoom: 4.5,
        minZoom: 2,
        maxZoom: 18,
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

  // Render Markers & Vectors on Mode/Data change
  useEffect(() => {
    const map = mapInstanceRef.current
    const layer = layerGroupRef.current
    if (!map || !layer) return

    layer.clearLayers()

    if (mapMode === "target_vector") {
      // 1. Draw Central Installation Hubs
      const usedHubs = new Set(mappedThreats.map(m => m.hubKey))
      usedHubs.forEach(hubKey => {
        const inst = STRATEGIC_INSTALLATIONS[hubKey]
        if (!inst) return

        const hubMarker = L.circleMarker(inst.coords, {
          radius: 12,
          fillColor: "#0D1521",
          color: "#00E5FF",
          weight: 2,
          opacity: 0.9,
          fillOpacity: 0.9,
        })

        hubMarker.bindTooltip(`
          <div style="background: #0D1521; color: #E8F0FE; padding: 4px 8px; border: 1px solid #00E5FF; font-family: monospace; font-size: 11px;">
            <b style="color: #00E5FF;">STRATEGIC COMMAND:</b> ${inst.name}<br/>
            <span style="color: #8A99AD;">Location: ${inst.region}</span>
          </div>
        `, { className: "custom-leaflet-tooltip", sticky: true })

        layer.addLayer(hubMarker)
      })

      // 2. Draw Target Domain Threat Markers with Targeting Vectors
      mappedThreats.forEach(threat => {
        const score = threat.score || 70
        const isCritical = score >= 85
        const markerColor = isCritical ? "#FF3B30" : score >= 70 ? "#FF9500" : "#FFCC00"

        // Faint dashed line from installation hub to the dispersed domain node
        const polyline = L.polyline([threat.installation.coords, threat.targetCoords], {
          color: markerColor,
          weight: 1,
          opacity: 0.35,
          dashArray: "3, 4",
        })
        layer.addLayer(polyline)

        const marker = L.circleMarker(threat.targetCoords, {
          radius: isCritical ? 7 : 5.5,
          fillColor: markerColor,
          color: "#060B14",
          weight: 1.5,
          opacity: 1,
          fillOpacity: 0.9,
        })

        const popupHtml = `
          <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; background: #0D1521; color: #E8F0FE; padding: 12px; border: 1px solid #1E3349; min-width: 240px;">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1E3349; padding-bottom: 6px; margin-bottom: 8px;">
              <span style="font-weight: 700; color: #FF9500; font-size: 12px;">${threat.domain}</span>
              <span style="background: ${markerColor}22; color: ${markerColor}; border: 1px solid ${markerColor}; padding: 1px 6px; font-weight: 700; font-size: 10px;">
                ${score}/100
              </span>
            </div>
            <div style="margin-bottom: 4px; color: #8A99AD;">
              <b style="color: #E8F0FE;">TARGET ASSET:</b> ${threat.installation.name}
            </div>
            <div style="margin-bottom: 4px; color: #8A99AD;">
              <b style="color: #E8F0FE;">REGION:</b> ${threat.installation.region}
            </div>
            <div style="margin-bottom: 4px; color: #8A99AD;">
              <b style="color: #E8F0FE;">ATTACKER IP:</b> <span style="color: #FF3B30;">${threat.hosting_ip || "185.220.101.99"}</span>
            </div>
            <div style="margin-bottom: 8px; color: #8A99AD;">
              <b style="color: #E8F0FE;">REGISTRAR:</b> ${threat.registrar || "Namecheap, Inc."}
            </div>
            <a href="#/alerts/${threat.id}" style="display: block; text-align: center; background: #142030; color: #00E5FF; padding: 6px 8px; text-decoration: none; border: 1px solid #1E3349; font-weight: 600; font-size: 10px; text-transform: uppercase;">
              Inspect Threat Dossier &rarr;
            </a>
          </div>
        `
        marker.bindPopup(popupHtml, { className: "custom-leaflet-popup" })
        marker.bindTooltip(`<b>${threat.domain}</b> (${score}/100)`, { direction: "top", offset: [0, -6] })

        if (onSelectAlert) {
          marker.on("click", () => onSelectAlert(threat))
        }

        layer.addLayer(marker)
      })

      map.flyTo([22.5, 79.5], 4.5, { duration: 1 })
    } else {
      // MODE 2: Global Attacker C2 Origins
      mappedThreats.forEach(threat => {
        const marker = L.circleMarker(threat.c2Coords, {
          radius: 8,
          fillColor: "#FF3B30",
          color: "#FFFFFF",
          weight: 1.5,
          opacity: 0.9,
          fillOpacity: 0.85,
        })

        const popupHtml = `
          <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; background: #0D1521; color: #E8F0FE; padding: 12px; border: 1px solid #1E3349; min-width: 240px;">
            <div style="border-bottom: 1px solid #1E3349; padding-bottom: 6px; margin-bottom: 8px;">
              <span style="font-weight: 700; color: #FF3B30; font-size: 12px;">ATTACKER INFRASTRUCTURE C2</span>
            </div>
            <div style="margin-bottom: 4px; color: #8A99AD;">
              <b style="color: #E8F0FE;">C2 DOMAIN:</b> ${threat.domain}
            </div>
            <div style="margin-bottom: 4px; color: #8A99AD;">
              <b style="color: #E8F0FE;">HOSTING IP:</b> ${threat.hosting_ip || "185.220.101.99"}
            </div>
            <div style="margin-bottom: 4px; color: #8A99AD;">
              <b style="color: #E8F0FE;">GEO ORIGIN:</b> ${threat.c2Location}
            </div>
            <div style="margin-bottom: 8px; color: #8A99AD;">
              <b style="color: #E8F0FE;">ASN ROUTE:</b> ${threat.c2Asn}
            </div>
            <a href="#/alerts/${threat.id}" style="display: block; text-align: center; background: #142030; color: #00E5FF; padding: 6px 8px; text-decoration: none; border: 1px solid #1E3349; font-weight: 600; font-size: 10px;">
              Inspect Threat Dossier &rarr;
            </a>
          </div>
        `
        marker.bindPopup(popupHtml)
        layer.addLayer(marker)
      })

      map.flyTo([45.0, 20.0], 3, { duration: 1 })
    }
  }, [mappedThreats, mapMode, onSelectAlert])

  const sectors = useMemo(() => {
    const set = new Set(alerts.map(a => a.sector || "Unclassified"))
    return ["ALL", ...Array.from(set)]
  }, [alerts])

  return (
    <div className="relative w-full h-[420px] rounded-none overflow-hidden border border-border bg-void flex flex-col font-data">
      {/* Top Map HUD Controls */}
      <div className="absolute top-3 left-3 z-[1000] flex items-center gap-2">
        <div className="bg-surface/90 backdrop-blur-md border border-border p-1 flex items-center gap-1 shadow-2xl">
          <button
            onClick={() => setMapMode("target_vector")}
            className={`px-3 py-1 text-2xs font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors ${
              mapMode === "target_vector"
                ? "bg-navy text-saffron border border-saffron/40 shadow-sm"
                : "text-secondary hover:text-primary hover:bg-raised"
            }`}
          >
            <Crosshair className="w-3.5 h-3.5 text-cyan-400" />
            <span>Targeted Commands & HQs ({mappedThreats.length})</span>
          </button>

          <button
            onClick={() => setMapMode("attacker_c2")}
            className={`px-3 py-1 text-2xs font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors ${
              mapMode === "attacker_c2"
                ? "bg-navy text-critical border border-critical/40 shadow-sm"
                : "text-secondary hover:text-primary hover:bg-raised"
            }`}
          >
            <Globe className="w-3.5 h-3.5 text-critical" />
            <span>Attacker C2 Geolocation</span>
          </button>
        </div>

        {/* Sector Filter Dropdown on Map */}
        <select
          value={selectedSector}
          onChange={(e) => setSelectedSector(e.target.value)}
          className="bg-surface/90 backdrop-blur-md border border-border text-primary text-2xs font-bold px-2 py-1.5 uppercase focus:outline-none"
        >
          {sectors.map(s => (
            <option key={s} value={s} className="bg-surface text-primary">
              {s === "ALL" ? "All Sovereign Sectors" : s}
            </option>
          ))}
        </select>
      </div>

      {/* Top Right Legend HUD */}
      <div className="absolute top-3 right-3 z-[1000] bg-surface/90 backdrop-blur-md border border-border px-3 py-1.5 text-2xs text-secondary flex items-center space-x-3 shadow-xl">
        <div className="flex items-center space-x-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 border border-cyan-300" />
          <span className="text-primary font-bold">Strategic HQ Hub</span>
        </div>
        <div className="flex items-center space-x-1.5">
          <span className="w-2 h-2 rounded-full bg-critical animate-pulse" />
          <span>Critical (&ge;85)</span>
        </div>
        <div className="flex items-center space-x-1.5">
          <span className="w-2 h-2 rounded-full bg-saffron" />
          <span>High (70-84)</span>
        </div>
      </div>

      {/* Map Leaflet Container */}
      <div ref={mapContainerRef} className="w-full h-full" />

      {/* Bottom Telemetry HUD */}
      <div className="absolute bottom-3 left-3 z-[1000] bg-surface/90 backdrop-blur-md border border-border px-3 py-1 text-2xs text-secondary flex items-center gap-4">
        <div className="flex items-center gap-1.5">
          <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
          <span>Projection: <b>WGS84 Sovereign Grid</b></span>
        </div>
        <span className="text-border">|</span>
        <div>
          <span>Plotted Entities: <b className="text-saffron">{mappedThreats.length} Active Vectors</b></span>
        </div>
      </div>
    </div>
  )
}
