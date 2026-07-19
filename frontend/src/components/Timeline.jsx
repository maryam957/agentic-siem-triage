/**
 * Vertical event timeline shown in the alert details panel.
 * Expects items shaped like { timestamp, event }.
 */
function Timeline({ items }) {
  if (!items || items.length === 0) {
    return <p className="text-sm text-muted">No timeline events recorded.</p>
  }

  return (
    <ol className="relative border-l border-border ml-2">
      {items.map((item, idx) => (
        <li key={idx} className="ml-4 pb-4 last:pb-0">
          <span className="absolute -left-[5px] mt-1.5 w-2.5 h-2.5 rounded-full bg-accent border border-canvas" />
          <p className="text-xs mono text-muted">{formatTimestamp(item.timestamp)}</p>
          <p className="text-sm text-ink">{item.event}</p>
        </li>
      ))}
    </ol>
  )
}

function formatTimestamp(ts) {
  if (!ts) return '--:--'
  try {
    const date = new Date(ts)
    if (Number.isNaN(date.getTime())) return ts
    return date.toLocaleString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    })
  } catch {
    return ts
  }
}

export default Timeline
