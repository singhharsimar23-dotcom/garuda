import React from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "react-hot-toast"
import { ShieldAlert } from "lucide-react"

import AlertTable from "../components/AlertTable"
import { getAlerts, confirmAlert, rejectAlert } from "../lib/api"
import { useGarudaStore } from "../store/useGarudaStore"

export default function Alerts() {
  const queryClient = useQueryClient()
  const { alerts, setAlerts, updateAlert } = useGarudaStore()

  const { data, isLoading } = useQuery({
    queryKey: ["alertsList"],
    queryFn: () => getAlerts({ limit: 100 }),
    refetchInterval: 15000,
  })

  // Mutation: Confirm Alert
  const confirmMutation = useMutation({
    mutationFn: (alert) =>
      confirmAlert({
        alert_id: alert.id,
        analyst_id: "soc_analyst_triage",
        justification: "Confirmed malicious threat infrastructure staging impersonation attack.",
      }),
    onSuccess: (resData, variables) => {
      updateAlert(variables.id, { status: "confirmed" })
      toast.success(`Alert confirmed! Advisory generated for ${variables.domain}`)
      queryClient.invalidateQueries({ queryKey: ["alertsList"] })
      queryClient.invalidateQueries({ queryKey: ["alerts"] })
      queryClient.invalidateQueries({ queryKey: ["stats"] })
    },
    onError: (err) => {
      toast.error(`Confirmation failed: ${err.message}`)
    },
  })

  // Mutation: Reject Alert
  const rejectMutation = useMutation({
    mutationFn: (alert) =>
      rejectAlert({
        alert_id: alert.id,
        analyst_id: "soc_analyst_triage",
        justification: "Benign authorized domain / false positive.",
        reason_code: "known_whitelist",
      }),
    onSuccess: (resData, variables) => {
      updateAlert(variables.id, { status: "false_positive" })
      toast.success(`Alert marked as false positive: ${variables.domain}`)
      queryClient.invalidateQueries({ queryKey: ["alertsList"] })
      queryClient.invalidateQueries({ queryKey: ["alerts"] })
      queryClient.invalidateQueries({ queryKey: ["stats"] })
    },
    onError: (err) => {
      toast.error(`Rejection failed: ${err.message}`)
    },
  })

  const alertItems = data?.alerts?.length > 0 ? data.alerts : alerts

  return (
    <div className="space-y-6 pb-12">
      <div className="bg-navy-900/60 border border-navy-800 p-5 rounded-2xl shadow-xl">
        <h2 className="text-xl font-black tracking-tight text-white flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-red-400" />
          <span>Threat Indicators Stream</span>
        </h2>
        <p className="text-xs text-gray-400 mt-1">
          High-velocity proactive domain staging alerts triaged through 11-step scoring pipeline
        </p>
      </div>

      <AlertTable
        alerts={alertItems}
        isLoading={isLoading}
        onConfirm={(alert) => confirmMutation.mutate(alert)}
        onReject={(alert) => rejectMutation.mutate(alert)}
      />
    </div>
  )
}
