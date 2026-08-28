import { describe, it, expect } from "vitest"
import { render, screen, waitFor } from "@testing-library/react"
import { HashRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"

import OrbTracker from "../OrbTracker"
import MalwareHunt from "../MalwareHunt"
import AttributionDashboard from "../AttributionDashboard"
import PredictiveDashboard from "../PredictiveDashboard"
import LifecycleDashboard from "../LifecycleDashboard"

function renderPage(Component) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <HashRouter>
        <Component />
      </HashRouter>
    </QueryClientProvider>
  )
}

describe("Dashboard pages — empty API responses", () => {
  it("OrbTracker renders without crash when nodes array is empty", async () => {
    renderPage(OrbTracker)
    await waitFor(() => {
      expect(screen.getByText(/ORB Network Tracker/i)).toBeInTheDocument()
    })
    expect(screen.getByText(/No ORB nodes flagged/i)).toBeInTheDocument()
  })

  it("MalwareHunt renders without crash when SSH groups are empty", async () => {
    renderPage(MalwareHunt)
    await waitFor(() => {
      expect(screen.getByText(/Malware Hunt Engine/i)).toBeInTheDocument()
    })
    expect(screen.getByText(/No SSH key reuse detected/i)).toBeInTheDocument()
  })

  it("AttributionDashboard renders without crash when graph is empty", async () => {
    renderPage(AttributionDashboard)
    await waitFor(() => {
      expect(screen.getByText(/Persona Attribution Graph/i)).toBeInTheDocument()
    })
    expect(screen.getByText(/No persona nodes indexed/i)).toBeInTheDocument()
  })

  it("PredictiveDashboard renders without crash when candidates are empty", async () => {
    renderPage(PredictiveDashboard)
    await waitFor(() => {
      expect(screen.getByText(/Predictive Domain Pre-Registration/i)).toBeInTheDocument()
    })
    expect(screen.getByText(/No predictive candidates/i)).toBeInTheDocument()
  })

  it("LifecycleDashboard renders without crash when summary is empty", async () => {
    renderPage(LifecycleDashboard)
    await waitFor(() => {
      expect(screen.getByText(/Campaign Lifecycle Tracker/i)).toBeInTheDocument()
    })
    expect(screen.getByText(/No confirmed IOCs tracked/i)).toBeInTheDocument()
  })
})
