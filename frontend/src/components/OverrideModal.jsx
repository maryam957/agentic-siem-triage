import { useState } from 'react'
import { X } from 'lucide-react'

const SEVERITY_OPTIONS = ['low', 'medium', 'high', 'critical']

/**
 * Modal for submitting an analyst override: new severity + comment.
 */
function OverrideModal({ alert, onCancel, onSubmit, submitting }) {
  const [newSeverity, setNewSeverity] = useState('low')
  const [comment, setComment] = useState('')

  if (!alert) return null

  const handleSubmit = (e) => {
    e.preventDefault()
    onSubmit(alert.alert_id, { new_severity: newSeverity, comment })
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4">
      <div className="bg-panel border border-border rounded-md w-full max-w-md p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-ink">
            Override Decision — <span className="mono">{alert.alert_id}</span>
          </h3>
          <button onClick={onCancel} className="text-muted hover:text-ink">
            <X size={16} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div>
            <label className="block text-xs text-muted uppercase tracking-wide mb-1.5">
              New Severity
            </label>
            <select
              value={newSeverity}
              onChange={(e) => setNewSeverity(e.target.value)}
              className="w-full bg-slate-800/60 border border-border rounded-md px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-accent"
            >
              {SEVERITY_OPTIONS.map((opt) => (
                <option key={opt} value={opt} className="bg-panel">
                  {opt.charAt(0).toUpperCase() + opt.slice(1)}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs text-muted uppercase tracking-wide mb-1.5">
              Comment
            </label>
            <textarea
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              rows={3}
              placeholder="Explain the reason for this override..."
              className="w-full bg-slate-800/60 border border-border rounded-md px-3 py-2 text-sm text-ink placeholder:text-muted/60 focus:outline-none focus:ring-1 focus:ring-accent resize-none"
            />
          </div>

          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onCancel}
              className="px-3 py-1.5 text-sm rounded-md border border-border text-muted hover:text-ink hover:bg-slate-800/40"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-3 py-1.5 text-sm rounded-md bg-accent text-white hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submitting ? 'Submitting...' : 'Submit Override'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default OverrideModal
