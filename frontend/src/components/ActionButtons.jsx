import { Check, RotateCcw, ShieldAlert, Loader2 } from 'lucide-react'

/**
 * Approve / Override / Reinvestigate action buttons.
 * `pendingAction` is the name of the action currently in flight
 * for this alert (or null), used to show a spinner and disable
 * the other buttons while a request is outstanding.
 */
function ActionButtons({ onApprove, onOverride, onReinvestigate, pendingAction, size = 'sm' }) {
  const isBusy = Boolean(pendingAction)
  const padding = size === 'sm' ? 'px-2.5 py-1 text-xs' : 'px-3 py-1.5 text-sm'

  return (
    <div className="flex items-center gap-1.5">
      <button
        onClick={onApprove}
        disabled={isBusy}
        className={`inline-flex items-center gap-1 rounded border border-border ${padding} font-medium text-green-400 hover:bg-green-600/10 hover:border-green-600/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors`}
      >
        {pendingAction === 'approve' ? (
          <Loader2 size={13} className="animate-spin" />
        ) : (
          <Check size={13} />
        )}
        Approve
      </button>

      <button
        onClick={onOverride}
        disabled={isBusy}
        className={`inline-flex items-center gap-1 rounded border border-border ${padding} font-medium text-yellow-400 hover:bg-yellow-600/10 hover:border-yellow-600/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors`}
      >
        {pendingAction === 'override' ? (
          <Loader2 size={13} className="animate-spin" />
        ) : (
          <ShieldAlert size={13} />
        )}
        Override
      </button>

      <button
        onClick={onReinvestigate}
        disabled={isBusy}
        className={`inline-flex items-center gap-1 rounded border border-border ${padding} font-medium text-blue-400 hover:bg-blue-600/10 hover:border-blue-600/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors`}
      >
        {pendingAction === 'reinvestigate' ? (
          <Loader2 size={13} className="animate-spin" />
        ) : (
          <RotateCcw size={13} />
        )}
        Reinvestigate
      </button>
    </div>
  )
}

export default ActionButtons
