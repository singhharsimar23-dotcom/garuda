import React from "react"

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error("[GARUDA ErrorBoundary Caught Error]:", error, errorInfo)
  }

  handleReset = () => {
    try {
      localStorage.clear()
      sessionStorage.clear()
    } catch (e) {
      console.warn("Storage clear error:", e)
    }
    window.location.href = window.location.origin + "/#/operations"
    window.location.reload()
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          className="flex flex-col items-center justify-center min-h-screen p-6 font-mono select-none"
          style={{ background: "#060B14", color: "#E8F0FE" }}
        >
          <div
            className="max-w-md w-full p-6 border border-border"
            style={{ background: "#0D1521" }}
          >
            <div className="flex items-center gap-2 mb-4 text-critical font-bold text-sm tracking-wider uppercase">
              <span className="inline-block w-2 h-2 rounded-full bg-critical animate-pulse" />
              Runtime Recovery Active
            </div>
            <p className="text-xs text-secondary mb-4 leading-relaxed">
              A stale browser cache or hydration mismatch occurred during profile reload.
            </p>
            <div className="p-3 mb-4 bg-void border border-border text-2xs text-ghost overflow-x-auto">
              {this.state.error?.message || "Unknown client execution anomaly"}
            </div>
            <button
              onClick={this.handleReset}
              className="w-full py-2.5 px-4 bg-saffron text-void font-bold text-xs uppercase tracking-widest hover:brightness-110 transition-all cursor-pointer"
            >
              Flush Cache & Restore Platform
            </button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
