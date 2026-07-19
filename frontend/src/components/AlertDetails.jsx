import SeverityBadge from './SeverityBadge.jsx'
import Timeline from './Timeline.jsx'
import ActionButtons from './ActionButtons.jsx'
import { FileSearch, ShieldCheck, ListChecks, Clock3 } from 'lucide-react'

/**
 * Right-hand panel showing full detail for the selected alert.
 */
function AlertDetails({ alert, onApprove, onOverride, onReinvestigate, pendingAction }) {
  if (!alert) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-muted py-20">
        <FileSearch size={28} className="mb-2 opacity-60" />
        <p className="text-sm">Select an alert to view details.</p>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-muted uppercase tracking-wide mb-1">Alert ID</p>
          <h3 className="text-lg font-semibold mono text-ink">{alert.alert_id}</h3>
        </div>
        <SeverityBadge severity={alert.severity_label} />
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="bg-slate-800/40 border border-border rounded-md px-3 py-2">
          <p className="text-xs text-muted uppercase tracking-wide">Risk Score</p>
          <p className="text-xl font-semibold mono text-ink">{alert.score}</p>
        </div>
        <div className="bg-slate-800/40 border border-border rounded-md px-3 py-2">
          <p className="text-xs text-muted uppercase tracking-wide">Severity</p>
          <p className="text-xl font-semibold capitalize text-ink">{alert.severity_label}</p>
        </div>
      </div>

      <Section icon={ShieldCheck} title="MITRE ATT&CK">
        {alert.ttps && alert.ttps.length > 0 ? (
          <div className="flex flex-wrap gap-1.5">
            {alert.ttps.map((ttp) => (
              <span
                key={ttp}
                className="mono text-xs px-2 py-0.5 rounded border border-border bg-slate-800/40 text-ink"
              >
                {ttp}
              </span>
            ))}
          </div>
        ) : (
          <p className="text-sm text-muted">No techniques mapped.</p>
        )}
      </Section>

      <Section icon={FileSearch} title="Reasoning">
        <p className="text-sm text-ink/90 leading-relaxed">{alert.reasoning}</p>
      </Section>

      <Section icon={ListChecks} title="Recommended Actions">
        {alert.recommended_actions && alert.recommended_actions.length > 0 ? (
          <ul className="text-sm text-ink/90 space-y-1 list-disc list-inside">
            {alert.recommended_actions.map((action, idx) => (
              <li key={idx}>{action}</li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted">No recommended actions.</p>
        )}
      </Section>

      <Section icon={Clock3} title="Timeline">
        <Timeline items={alert.timeline} />
      </Section>

      <div className="pt-2 border-t border-border">
        <ActionButtons
          size="md"
          pendingAction={pendingAction}
          onApprove={() => onApprove(alert.alert_id)}
          onOverride={() => onOverride(alert)}
          onReinvestigate={() => onReinvestigate(alert.alert_id)}
        />
      </div>
    </div>
  )
}

function Section({ icon: Icon, title, children }) {
  return (
    <div>
      <div className="flex items-center gap-1.5 mb-2">
        <Icon size={14} className="text-muted" />
        <p className="text-xs text-muted uppercase tracking-wide font-medium">{title}</p>
      </div>
      {children}
    </div>
  )
}

export default AlertDetails
