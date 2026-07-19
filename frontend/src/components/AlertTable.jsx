import SeverityBadge from './SeverityBadge.jsx'
import ActionButtons from './ActionButtons.jsx'
import { Inbox } from 'lucide-react'

/**
 * Left-hand alert queue table.
 * `pendingActions` maps alert_id -> action name currently in flight.
 */
function AlertTable({
  alerts,
  selectedAlertId,
  onSelectAlert,
  onApprove,
  onOverride,
  onReinvestigate,
  pendingActions,
  statusByAlertId,
}) {
  if (!alerts || alerts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-muted">
        <Inbox size={28} className="mb-2 opacity-60" />
        <p className="text-sm">No alerts awaiting review.</p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm border-collapse">
        <thead>
          <tr className="text-left text-xs text-muted uppercase tracking-wide border-b border-border">
            <th className="py-2 pr-4 font-medium">Alert ID</th>
            <th className="py-2 pr-4 font-medium">Severity</th>
            <th className="py-2 pr-4 font-medium">Score</th>
            <th className="py-2 pr-4 font-medium">Status</th>
            <th className="py-2 pr-4 font-medium">Action</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => {
            const isSelected = alert.alert_id === selectedAlertId
            const status = statusByAlertId?.[alert.alert_id] || 'pending'

            return (
              <tr
                key={alert.alert_id}
                onClick={() => onSelectAlert(alert.alert_id)}
                className={`border-b border-border/60 cursor-pointer transition-colors ${
                  isSelected ? 'bg-slate-800/50' : 'hover:bg-slate-800/25'
                }`}
              >
                <td className="py-2.5 pr-4 mono text-ink">{alert.alert_id}</td>
                <td className="py-2.5 pr-4">
                  <SeverityBadge severity={alert.severity_label} />
                </td>
                <td className="py-2.5 pr-4 mono text-ink">{alert.score}</td>
                <td className="py-2.5 pr-4">
                  <StatusPill status={status} />
                </td>
                <td className="py-2.5 pr-4" onClick={(e) => e.stopPropagation()}>
                  <ActionButtons
                    pendingAction={pendingActions?.[alert.alert_id]}
                    onApprove={() => onApprove(alert.alert_id)}
                    onOverride={() => onOverride(alert)}
                    onReinvestigate={() => onReinvestigate(alert.alert_id)}
                  />
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function StatusPill({ status }) {
  const styles = {
    pending: 'text-slate-300 bg-slate-700/40',
    approved: 'text-green-400 bg-green-600/10',
    overridden: 'text-yellow-400 bg-yellow-600/10',
    reinvestigating: 'text-blue-400 bg-blue-600/10',
  }

  return (
    <span className={`text-xs px-2 py-0.5 rounded ${styles[status] || styles.pending}`}>
      {status}
    </span>
  )
}

export default AlertTable
