import type { Severity } from '../../types'

interface SeverityBadgeProps {
  severity: Severity
  size?: 'sm' | 'md'
}

const config: Record<Severity, { label: string; classes: string; dot: string }> = {
  critical: {
    label: 'Critical',
    classes: 'bg-red-950/60 text-red-300 border-red-800/80',
    dot: 'bg-red-400',
  },
  high: {
    label: 'High',
    classes: 'bg-orange-950/60 text-orange-300 border-orange-800/80',
    dot: 'bg-orange-400',
  },
  medium: {
    label: 'Medium',
    classes: 'bg-amber-950/60 text-amber-300 border-amber-800/80',
    dot: 'bg-amber-400',
  },
  low: {
    label: 'Low',
    classes: 'bg-cyan-950/60 text-cyan-300 border-cyan-800/80',
    dot: 'bg-cyan-400',
  },
  info: {
    label: 'Info',
    classes: 'bg-zinc-800 text-zinc-300 border-zinc-700',
    dot: 'bg-zinc-400',
  },
}

export default function SeverityBadge({ severity, size = 'sm' }: SeverityBadgeProps) {
  const { label, classes, dot } = config[severity] ?? config.info
  const textSize = size === 'sm' ? 'text-sm' : 'text-base'
  const padding  = size === 'sm' ? 'px-2.5 py-0.5' : 'px-3 py-1'

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono font-medium border rounded whitespace-nowrap
                  ${textSize} ${padding} ${classes}`}
    >
      <span className={`w-2 h-2 rounded-full shrink-0 ${dot}`} />
      {label}
    </span>
  )
}
