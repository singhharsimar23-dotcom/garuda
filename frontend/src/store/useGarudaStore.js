import { create } from "zustand"

export const useGarudaStore = create((set) => ({
  alerts: [],
  campaigns: [],
  stats: {
    total_alerts_24h: 0,
    critical_24h: 0,
    confirmed_24h: 0,
    false_positive_rate_7d: 0.0,
    active_campaigns: 0,
    tension_index: 0.50,
    conflict_mode: false,
    domains_monitored: 110,
    last_collection_at: null,
  },
  systemHealth: {},
  activeAlert: null,

  filters: {
    status: "all",
    scoreMin: 0,
    sector: "",
    search: "",
  },
  tensionIndex: 0.50,
  conflictMode: false,
  realtimeConnected: false,

  setAlerts: (alerts) => set({ alerts }),

  addAlert: (newAlert) =>
    set((state) => {
      if (!newAlert || !newAlert.id) return state
      // Avoid duplicate alert records
      const exists = state.alerts.some((a) => a.id === newAlert.id)
      if (exists) {
        return {
          alerts: state.alerts.map((a) => (a.id === newAlert.id ? { ...a, ...newAlert } : a)),
        }
      }
      return {
        alerts: [newAlert, ...state.alerts],
        stats: {
          ...state.stats,
          total_alerts_24h: (state.stats.total_alerts_24h || 0) + 1,
          critical_24h: (newAlert.score >= 85) ? (state.stats.critical_24h || 0) + 1 : state.stats.critical_24h,
        },
      }
    }),

  updateAlert: (id, updates) =>
    set((state) => ({
      alerts: state.alerts.map((a) =>
        a.id === id || String(a.id).startsWith(id) ? { ...a, ...updates } : a
      ),
      activeAlert:
        state.activeAlert && (state.activeAlert.id === id || String(state.activeAlert.id).startsWith(id))
          ? { ...state.activeAlert, ...updates }
          : state.activeAlert,
    })),

  setCampaigns: (campaigns) => set({ campaigns }),

  setStats: (stats) =>
    set((state) => ({
      stats: { ...state.stats, ...stats },
      tensionIndex: stats.tension_index !== undefined ? stats.tension_index : state.tensionIndex,
      conflictMode: stats.conflict_mode !== undefined ? stats.conflict_mode : state.conflictMode,
    })),

  setSystemHealth: (systemHealth) => set({ systemHealth }),

  setActiveAlert: (activeAlert) => set({ activeAlert }),

  setFilters: (newFilters) =>
    set((state) => ({
      filters: { ...state.filters, ...newFilters },
    })),

  setTensionIndex: (tensionIndex) => set({ tensionIndex }),
  setConflictMode: (conflictMode) => set({ conflictMode }),
  setRealtimeConnected: (realtimeConnected) => set({ realtimeConnected }),
}))
