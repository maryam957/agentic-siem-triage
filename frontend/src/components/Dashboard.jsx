import { useEffect, useState, useCallback, useMemo } from 'react'
import { ShieldAlert, Clock4, TrendingUp, Layers, RefreshCcw, AlertTriangle } from 'lucide-react'
import StatsCard from './StatsCard.jsx'
import AlertTable from './AlertTable.jsx'
import AlertDetails from './AlertDetails.jsx'
import OverrideModal from './OverrideModal.jsx'
import { getAlerts, approveAlert, overrideAlert, reinvestigateAlert } from '../api/api.js'

function Dashboard() {
  const [alerts, setAlerts] = useState([])
  const [selectedAlertId, setSelectedAlertId] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const [pendingActions, setPendingActions] = useState({}) // alert_id -> action name
  const [statusByAlertId, setStatusByAlertId] = useState({}) // alert_id -> status
  const [overrideTarget, setOverrideTarget] = useState(null) // alert object or null

  const fetchAlerts = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getAlerts()
      setAlerts(data || [])
      if (!selectedAlertId && data && data.length > 0) {
        setSelectedAlertId(data[0].alert_id)
      }
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          'Failed to load alerts. Is the backend running on localhost:8000?'
      )
    } finally {
      setLoading(false)
    }
  }, [selectedAlertId])

  useEffect(() => {
    fetchAlerts()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const setActionState = (alertId, action) => {
    setPendingActions((prev) => ({ ...prev, [alertId]: action }))
  }

  const clearActionState = (alertId) => {
    setPendingActions((prev) => {
      const next = { ...prev }
      delete next[alertId]
      return next
    })
  }

  const handleApprove = async (alertId) => {
    setActionState(alertId, 'approve')
    try {
      await approveAlert(alertId)
      setStatusByAlertId((prev) => ({ ...prev, [alertId]: 'approved' }))
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || 'Failed to approve alert.')
    } finally {
      clearActionState(alertId)
    }
  }

  const handleOverrideClick = (alert) => {
    setOverrideTarget(alert)
  }

  const handleOverrideSubmit = async (alertId, data) => {
    setActionState(alertId, 'override')
    try {
      await overrideAlert(alertId, data)
      setStatusByAlertId((prev) => ({ ...prev, [alertId]: 'overridden' }))
      setAlerts((prev) =>
        prev.map((a) =>
          a.alert_id === alertId ? { ...a, severity_label: data.new_severity } : a
        )
      )
      setOverrideTarget(null)
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || 'Failed to override alert.')
    } finally {
      clearActionState(alertId)
    }
  }

  const handleReinvestigate = async (alertId) => {
    setActionState(alertId, 'reinvestigate')
    setStatusByAlertId((prev) => ({ ...prev, [alertId]: 'reinvestigating' }))
    try {
      await reinvestigateAlert(alertId)
      await fetchAlerts()
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || 'Failed to reinvestigate alert.')
    } finally {
      clearActionState(alertId)
    }
  }

  const selectedAlert = useMemo(
    () => alerts.find((a) => a.alert_id === selectedAlertId) || null,
    [alerts, selectedAlertId]
  )

  const stats = useMemo(() => {
    const total = alerts.length
    const pendingCount = alerts.filter(
      (a) => (statusByAlertId[a.alert_id] || 'pending') === 'pending'
    ).length
    const highRisk = alerts.filter((a) =>
      ['high', 'critical'].includes((a.severity_label || '').toLowerCase())
    ).length
    const avgScore =
      total > 0 ? Math.round(alerts.reduce((sum, a) => sum + (a.score || 0), 0) / total) : 0

    return { total, pendingCount, highRisk, avgScore }
  }, [alerts, statusByAlertId])

  return (
    <div className="min-h-screen bg-canvas text-ink flex flex-col">
      {/* Header */}
      <header className="border-b border-border bg-panel px-6 py-4 flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Agentic SIEM Triage</h1>
          <p className="text-xs text-muted">Security Operations Center</p>
        </div>
        <button
          onClick={fetchAlerts}
          disabled={loading}
          className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-border text-muted hover:text-ink hover:bg-slate-800/40 disabled:opacity-50"
        >
          <RefreshCcw size={13} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </header>

      {/* Error banner */}
      {error && (
        <div className="mx-6 mt-4 flex items-center gap-2 bg-red-600/10 border border-red-600/30 text-red-400 text-sm rounded-md px-4 py-2.5">
          <AlertTriangle size={15} />
          <span>{error}</span>
        </div>
      )}

      <main className="flex-1 px-6 py-5 flex flex-col gap-5">
        {/* Stats row */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatsCard label="Total Alerts" value={stats.total} icon={Layers} />
          <StatsCard label="Pending Review" value={stats.pendingCount} icon={Clock4} />
          <StatsCard
            label="High Risk"
            value={stats.highRisk}
            icon={ShieldAlert}
            accent="text-orange-400"
          />
          <StatsCard label="Average Score" value={stats.avgScore} icon={TrendingUp} />
        </div>

        {/* Main content */}
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-5 gap-5">
          <section className="lg:col-span-3 bg-panel border border-border rounded-md p-4">
            <h2 className="text-sm font-semibold text-ink mb-3">Alert Queue</h2>
            {loading ? (
              <LoadingRows />
            ) : (
              <AlertTable
                alerts={alerts}
                selectedAlertId={selectedAlertId}
                onSelectAlert={setSelectedAlertId}
                onApprove={handleApprove}
                onOverride={handleOverrideClick}
                onReinvestigate={handleReinvestigate}
                pendingActions={pendingActions}
                statusByAlertId={statusByAlertId}
              />
            )}
          </section>

          <section className="lg:col-span-2 bg-panel border border-border rounded-md p-4">
            <h2 className="text-sm font-semibold text-ink mb-3">Alert Details</h2>
            <AlertDetails
              alert={selectedAlert}
              onApprove={handleApprove}
              onOverride={handleOverrideClick}
              onReinvestigate={handleReinvestigate}
              pendingAction={selectedAlert ? pendingActions[selectedAlert.alert_id] : null}
            />
          </section>
        </div>
      </main>

      <OverrideModal
        alert={overrideTarget}
        onCancel={() => setOverrideTarget(null)}
        onSubmit={handleOverrideSubmit}
        submitting={overrideTarget ? Boolean(pendingActions[overrideTarget.alert_id]) : false}
      />
    </div>
  )
}

function LoadingRows() {
  return (
    <div className="flex flex-col gap-2 animate-pulse">
      {[...Array(4)].map((_, idx) => (
        <div key={idx} className="h-9 bg-slate-800/40 rounded-md" />
      ))}
    </div>
  )
}

export default Dashboard
