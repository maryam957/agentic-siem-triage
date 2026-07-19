const SEVERITY_STYLES = {
  critical: 'bg-red-600/15 text-red-400 border-red-600/40',
  high: 'bg-orange-600/15 text-orange-400 border-orange-600/40',
  medium: 'bg-yellow-600/15 text-yellow-400 border-yellow-600/40',
  low: 'bg-green-600/15 text-green-400 border-green-600/40',
}

/**
 * Small pill badge indicating alert severity.
 * Falls back to a neutral style for unrecognized values.
 */
function SeverityBadge({ severity }) {
  const key = (severity || '').toLowerCase()
  const style = SEVERITY_STYLES[key] || 'bg-slate-600/15 text-slate-300 border-slate-600/40'

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded border text-[11px] font-semibold uppercase tracking-wide ${style}`}
    >
      {severity || 'unknown'}
    </span>
  )
}

export default SeverityBadge
