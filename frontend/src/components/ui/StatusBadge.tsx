import type { ScanStatus, ReportStatus } from '../../types'

type Status = ScanStatus | ReportStatus

interface StatusBadgeProps {
  status: Status
}

const config: Record<Status, { label: string; classes: string }> = {
  completed:   { label: 'Completed',   classes: 'bg-emerald-950/60 text-emerald-300 border-emerald-800/80' },
  running:     { label: 'Running',     classes: 'bg-brand-950/60 text-brand-300 border-brand-800/80 animate-pulse' },
  failed:      { label: 'Failed',      classes: 'bg-red-950/60 text-red-300 border-red-800/80' },
  queued:      { label: 'Queued',      classes: 'bg-zinc-800 text-zinc-300 border-zinc-700' },
  cancelled:   { label: 'Cancelled',  classes: 'bg-zinc-800 text-zinc-400 border-zinc-700' },
  ready:       { label: 'Ready',       classes: 'bg-emerald-950/60 text-emerald-300 border-emerald-800/80' },
  generating:  { label: 'Generating', classes: 'bg-brand-950/60 text-brand-300 border-brand-800/80 animate-pulse' },
  unavailable: { label: 'Unavailable', classes: 'bg-zinc-800 text-zinc-400 border-zinc-700' },
}

export default function StatusBadge({ status }: StatusBadgeProps) {
  const { label, classes } = config[status] ?? {
    label: status,
    classes: 'bg-zinc-800 text-zinc-300 border-zinc-700',
  }

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 text-sm font-mono
                  font-medium border rounded whitespace-nowrap ${classes}`}
    >
      {label}
    </span>
  )
}
