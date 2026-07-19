/**
 * Top-of-dashboard statistic tile.
 * `accent` optionally tints the value text (e.g. for High Risk count).
 */
function StatsCard({ label, value, icon: Icon, accent }) {
  return (
    <div className="bg-panel border border-border rounded-md px-4 py-3 flex items-center justify-between">
      <div>
        <p className="text-xs text-muted uppercase tracking-wide mb-1">{label}</p>
        <p className={`text-2xl font-semibold ${accent || 'text-ink'}`}>{value}</p>
      </div>
      {Icon && (
        <div className="p-2 rounded-md bg-slate-800/60 border border-border">
          <Icon size={18} className="text-muted" />
        </div>
      )}
    </div>
  )
}

export default StatsCard
