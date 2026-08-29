// Clean relative API routing for both local dev and production serverless
const API_BASE = ""

export async function apiGet(path, params = {}) {
  const isBrowser = typeof window !== "undefined"
  const url = isBrowser 
    ? new URL(path, window.location.origin)
    : new URL(path, "http://localhost:8000")

  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.append(key, value)
    }
  })

  const response = await fetch(url.toString(), {
    method: "GET",
    headers: {
      "Accept": "application/json",
    },
  })

  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`API error ${response.status}: ${errorText}`)
  }

  return response.json()
}

export async function apiPost(path, body = {}) {
  const isBrowser = typeof window !== "undefined"
  const url = isBrowser 
    ? new URL(path, window.location.origin)
    : new URL(path, "http://localhost:8000")

  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
    },
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`API error ${response.status}: ${errorText}`)
  }

  return response.json()
}

// Alerts API
export const getAlerts = (params = {}) => apiGet("/api/alerts", params)
export const getAlert = (id) => apiGet(`/api/alerts/${id}`)
export const getAlertGraph = (id) => apiGet(`/api/alerts/${id}/graph`)
export const getAlertYara = async (id) => {
  const isBrowser = typeof window !== "undefined"
  const url = isBrowser 
    ? new URL(`/api/alerts/${id}/yara`, window.location.origin)
    : new URL(`/api/alerts/${id}/yara`, "http://localhost:8000")
  const res = await fetch(url.toString())
  return res.text()
}

// Analyst Triage API
export const confirmAlert = (payload) => apiPost("/api/analyst/confirm", payload)
export const rejectAlert = (payload) => apiPost("/api/analyst/reject", payload)
export const whitelistDomain = (payload) => apiPost("/api/analyst/whitelist", payload)
export const getAlertAudit = (id) => apiGet(`/api/analyst/audit/${id}`)

// Campaigns & Attack Clustering API
export const getCampaigns = () => apiGet("/api/campaigns")
export const getCampaign = (clusterId) => apiGet(`/api/campaigns/${clusterId}`)

// Threat Feed & Sharing
export const getStixFeed = () => apiGet("/api/stix/feed")
export const getStixAlert = (id) => apiGet(`/api/stix/${id}`)

// SOC Posture & Collection
export const getStats = () => apiGet("/api/stats")

// Dashboard data APIs
export const getOrbNodes = () => apiGet("/api/orb/nodes")
export const getSshGroups = () => apiGet("/api/malware_hunt/ssh")
export const getSandboxAnalyses = () => apiGet("/api/malware_hunt/sandbox")
export const getAttributionGraph = (cluster) =>
  apiGet("/api/attribution/graph", cluster ? { cluster } : {})
export const getPredictiveDomains = () => apiGet("/api/predictive/domains")
export const getLifecycleSummary = () => apiGet("/api/lifecycle/summary")

export const triggerCollection = () => apiPost("/api/collect")

// Retrohunt Historical Replay
export const runRetrohunt = () => apiPost("/api/retrohunt")
