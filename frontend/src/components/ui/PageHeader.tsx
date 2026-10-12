import type { ReactNode } from 'react'

interface PageHeaderProps {
  title: string
  description?: string
  action?: ReactNode
}

/**
 * PageHeader — consistent section heading used across all views.
 * Typography scale: 28–32px page title, 14–15px description.
 */
export default function PageHeader({ title, description, action }: PageHeaderProps) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6 pb-5 border-b border-surface-600/60">
      <div>
        <h2 className="text-2xl md:text-3xl font-bold tracking-tight text-zinc-100">{title}</h2>
        {description && (
          <p className="text-sm md:text-[15px] text-zinc-400 mt-1 leading-normal">{description}</p>
        )}
      </div>
      {action && <div className="flex items-center gap-2.5 shrink-0">{action}</div>}
    </div>
  )
}
