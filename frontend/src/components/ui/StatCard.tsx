import type { ReactNode } from 'react'

interface StatCardProps {
  title: string
  value: string | number
  subtitle?: string
  icon: ReactNode
  accentColor?: string
  isPlaceholder?: boolean
}

/**
 * StatCard — displays a single KPI metric with enterprise security styling.
 */
export default function StatCard({
  title,
  value,
  subtitle,
  icon,
  accentColor = 'text-zinc-100',
  isPlaceholder = false,
}: StatCardProps) {
  return (
    <div className="bg-surface-800 border border-surface-600/80 rounded-lg p-5 transition-colors hover:border-surface-500">
      <div className="flex items-center justify-between gap-3 mb-2.5">
        <p className="text-xs md:text-sm font-semibold text-zinc-400 uppercase tracking-wider">{title}</p>
        <div className="text-zinc-400 text-base">
          {icon}
        </div>
      </div>

      <div className="flex items-baseline gap-2">
        <p className={`text-3xl font-bold font-mono tracking-tight ${accentColor}`}>
          {value}
        </p>
      </div>

      {subtitle && (
        <p className="text-xs md:text-sm text-zinc-400 mt-1.5 truncate">{subtitle}</p>
      )}

      {isPlaceholder && (
        <div className="mt-3 pt-2.5 border-t border-surface-600/40">
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 text-xs rounded bg-amber-950/40 text-amber-300 border border-amber-800/40 font-mono">
            <span>•</span> placeholder data
          </span>
        </div>
      )}
    </div>
  )
}
