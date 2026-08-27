import React, { useEffect, useRef } from "react"
import L from "leaflet"

// Fixed coordinates for targeted Indian critical sectors / headquarters
const SECTOR_COORDINATES = {
  "National Defence": [28.6143, 77.2088],          // South Block, MoD, New Delhi
  "Ministry of Defence (MoD)": [28.6143, 77.2088], // South Block, New Delhi
  "Defence R&D (DRDO)": [18.5204, 73.8567],        // DRDO Armament / DIAT Pune
  "National Informatics Centre (NIC)": [28.5855, 77.2410], // CGO Complex, New Delhi
  "Paramilitary & Intelligence": [28.5880, 77.2280], // MHA / CGO Complex, New Delhi
  "Unclassified Critical Sector": [19.0760, 72.8777], // Mumbai Financial / Energy
}

// Fix Leaflet default icon asset URLs
delete L.Icon.Default.prototype._getIconUrl
L.Icon.Default.mergeOptions({
  iconRetinaUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png",
  iconUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
  shadowUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
})

export default function ThreatMap({ alerts = [], onSelectAlert }) {
  const mapContainerRef = useRef(null)
  const mapInstanceRef = useRef(null)
  const markersLayerRef = useRef(null)

  useEffect(() => {
    if (!mapContainerRef.current) return

    if (!mapInstanceRef.current) {
      const map = L.map(mapContainerRef.current, {
        center: [21.5, 78.9],
        zoom: 4,
        minZoom: 2,
        maxZoom: 18,
        zoomControl: true,
      })

      L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}", {
        attribution: '&copy; Esri &mdash; National Geographic, DeLorme, HERE',
        maxZoom: 16,
      }).addTo(map)

      markersLayerRef.current = L.layerGroup().addTo(map)
      mapInstanceRef.current = map
    }

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove()
        mapInstanceRef.current = null
      }
    }
  }, [])

  useEffect(() => {
    const map = mapInstanceRef.current
    const layer = markersLayerRef.current
    if (!map || !layer) return

    layer.clearLayers()

    alerts.forEach((alert) => {
      // Resolve coordinates: explicit alert coords > sector HQ coordinates > default South Block Delhi
      const sectorCoords = SECTOR_COORDINATES[alert.sector] || [28.6139, 77.2090]
      const lat = alert.lat || alert.signals?.latitude || sectorCoords[0]
      const lng = alert.lng || alert.signals?.longitude || sectorCoords[1]

      if (lat && lng) {
        const score = alert.score || 0
        const color = score >= 85 ? "#ef4444" : score >= 70 ? "#f97316" : "#eab308"
        const fillColor = score >= 85 ? "#dc2626" : score >= 70 ? "#ea580c" : "#ca8a04"

        const marker = L.circleMarker([lat, lng], {
          radius: score >= 85 ? 9 : 7,
          fillColor: fillColor,
          color: "#ffffff",
          weight: 1.5,
          opacity: 0.9,
          fillOpacity: 0.8,
        })

        const popupContent = `
          <div style="font-family: ui-sans-serif, system-ui; font-size: 12px; color: #1e293b; min-width: 200px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
              <span style="font-weight: 700; color: #0f172a; font-size: 13px;">${alert.domain}</span>
              <span style="background: ${color}; color: #fff; padding: 2px 6px; border-radius: 4px; font-weight: 700; font-size: 10px;">
                ${score}/100
              </span>
            </div>
            <div style="color: #475569; margin-bottom: 2px;"><b>Targeted Sector:</b> ${alert.sector || "National Defence"}</div>
            <div style="color: #475569; margin-bottom: 2px;"><b>Attacker Server IP:</b> <code>${alert.hosting_ip || "Unresolved"}</code></div>
            <div style="color: #475569; margin-bottom: 6px;"><b>Registrar:</b> ${alert.registrar || "Redacted"}</div>
            <a href="#/alerts/${alert.id}" style="display: inline-block; color: #2563eb; font-weight: 600; text-decoration: none; font-size: 11px;">
              Inspect Threat Dossier &rarr;
            </a>
          </div>
        `
        marker.bindPopup(popupContent)

        if (onSelectAlert) {
          marker.on("click", () => onSelectAlert(alert))
        }

        layer.addLayer(marker)
      }
    })
  }, [alerts, onSelectAlert])

  return (
    <div className="relative w-full h-full min-h-[380px] rounded-xl overflow-hidden border border-navy-700/60 shadow-xl bg-navy-900">
      <div ref={mapContainerRef} className="w-full h-full min-h-[380px]" />
      
      {/* Top Banner explaining the Map projection */}
      <div className="absolute top-3 left-3 z-[1000] bg-navy-950/85 backdrop-blur-md px-3 py-1.5 rounded-lg border border-navy-700/80 text-[11px] text-gray-300 shadow-lg">
        <span className="text-cyan-400 font-bold">Target Vector:</span> Targeted Indian Defense & Critical Infrastructure HQs
      </div>

      <div className="absolute top-3 right-3 z-[1000] bg-navy-950/85 backdrop-blur-md px-3 py-2 rounded-lg border border-navy-700/80 text-xs text-gray-300 flex items-center space-x-3 shadow-lg">
        <div className="flex items-center space-x-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse" />
          <span>Critical (&ge;85)</span>
        </div>
        <div className="flex items-center space-x-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-orange-500" />
          <span>High (70-84)</span>
        </div>
        <div className="flex items-center space-x-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-yellow-500" />
          <span>Medium (&lt;70)</span>
        </div>
      </div>
    </div>
  )
}
