import type { SeverityCount } from '../../types'

interface SeverityBarProps {
  counts: SeverityCount
  showLabels?: boolean
}

const SEVERITY_CONFIG = [
  { key: 'critical' as const, label: 'Critical', barColor: 'bg-red-500',    textColor: 'text-red-400'    },
  { key: 'high'     as const, label: 'High',     barColor: 'bg-orange-500', textColor: 'text-orange-400' },
  { key: 'medium'   as const, label: 'Medium',   barColor: 'bg-amber-500',  textColor: 'text-amber-400'  },
  { key: 'low'      as const, label: 'Low',      barColor: 'bg-cyan-500',   textColor: 'text-cyan-400'   },
  { key: 'info'     as const, label: 'Info',     barColor: 'bg-zinc-400',   textColor: 'text-zinc-300'   },
]

export default function SeverityBar({ counts, showLabels = true }: SeverityBarProps) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0)

  if (total === 0) {
    return (
      <p className="text-sm text-zinc-400 italic">No findings recorded.</p>
    )
  }

  return (
    <div className="space-y-4">
      {/* Segmented bar */}
      <div className="flex h-2.5 rounded bg-surface-700 overflow-hidden gap-0.5">
        {SEVERITY_CONFIG.map(({ key, barColor }) => {
          const pct = (counts[key] / total) * 100
          if (pct === 0) return null
          return (
            <div
              key={key}
              className={`${barColor}`}
              style={{ width: `${pct}%` }}
              aria-label={`${key}: ${counts[key]}`}
              title={`${key}: ${counts[key]}`}
            />
          )
        })}
      </div>

      {/* Per-row breakdown */}
      {showLabels && (
        <div className="space-y-2.5">
          {SEVERITY_CONFIG.map(({ key, label, barColor, textColor }) => {
            const count = counts[key]
            const pct   = total > 0 ? Math.round((count / total) * 100) : 0
            return (
              <div key={key} className="flex items-center gap-3 text-sm">
                <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${barColor}`} />
                <span className={`w-16 shrink-0 font-medium ${textColor}`}>{label}</span>
                <div className="flex-1 bg-surface-700 rounded h-2 overflow-hidden">
                  <div
                    className={`${barColor} h-2 transition-all duration-300`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <span className="w-8 text-right text-zinc-300 font-mono text-sm">{count}</span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
