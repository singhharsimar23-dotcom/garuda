import "@testing-library/jest-dom"

// Mock Leaflet — raw Leaflet via useEffect; jsdom has no canvas
vi.mock("leaflet", () => {
  const layerGroup = () => ({
    clearLayers: vi.fn(),
    addLayer: vi.fn(),
  })
  const map = {
    remove: vi.fn(),
    setView: vi.fn(),
  }
  return {
    default: {
      map: vi.fn(() => map),
      tileLayer: vi.fn(() => ({ addTo: vi.fn() })),
      control: { zoom: vi.fn(() => ({ addTo: vi.fn() })) },
      layerGroup: vi.fn(layerGroup),
      circleMarker: vi.fn(() => ({
        on: vi.fn().mockReturnThis(),
        bindTooltip: vi.fn().mockReturnThis(),
      })),
    },
  }
})

// Mock chart.js canvas
HTMLCanvasElement.prototype.getContext = vi.fn(() => ({
  fillRect: vi.fn(),
  clearRect: vi.fn(),
  getImageData: vi.fn(() => ({ data: [] })),
  putImageData: vi.fn(),
  createImageData: vi.fn(() => []),
  setTransform: vi.fn(),
  drawImage: vi.fn(),
  save: vi.fn(),
  restore: vi.fn(),
  beginPath: vi.fn(),
  moveTo: vi.fn(),
  lineTo: vi.fn(),
  closePath: vi.fn(),
  stroke: vi.fn(),
  translate: vi.fn(),
  scale: vi.fn(),
  rotate: vi.fn(),
  arc: vi.fn(),
  fill: vi.fn(),
  measureText: vi.fn(() => ({ width: 0 })),
  transform: vi.fn(),
  rect: vi.fn(),
  clip: vi.fn(),
}))

function emptyFetchResponse(data) {
  return Promise.resolve({
    ok: true,
    json: () => Promise.resolve(data),
  })
}

beforeEach(() => {
  global.fetch = vi.fn((url) => {
    if (url.includes("/api/orb/nodes")) {
      return emptyFetchResponse({ nodes: [], stats: { total: 0, probable: 0, confirmed: 0, targeting_india: 0 } })
    }
    if (url.includes("/api/malware_hunt/ssh")) {
      return emptyFetchResponse({ groups: [] })
    }
    if (url.includes("/api/malware_hunt/sandbox")) {
      return emptyFetchResponse({ analyses: [] })
    }
    if (url.includes("/api/attribution/graph")) {
      return emptyFetchResponse({ nodes: [], links: [], clusters: [] })
    }
    if (url.includes("/api/predictive/domains")) {
      return emptyFetchResponse({ candidates: [], registered: [], budget: { monthly_limit_usd: 50, spent_usd: 0, remaining_usd: 50 } })
    }
    if (url.includes("/api/lifecycle/summary")) {
      return emptyFetchResponse({ state_counts: {}, cluster_burn: [], effectiveness: {} })
    }
    return emptyFetchResponse({})
  })
})
