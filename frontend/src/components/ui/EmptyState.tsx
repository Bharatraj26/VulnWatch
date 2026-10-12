import type { ReactNode } from 'react'
import { Inbox } from 'lucide-react'

interface EmptyStateProps {
  title?: string
  description?: string
  icon?: ReactNode
  action?: ReactNode
}

/**
 * EmptyState — shown when a list/table has no records to display.
 */
export default function EmptyState({
  title = 'No records found',
  description = 'Nothing to display yet.',
  icon,
  action,
}: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center px-4">
      <div className="text-zinc-500 mb-3.5">
        {icon ?? <Inbox className="w-12 h-12 stroke-1" />}
      </div>
      <p className="text-lg font-semibold text-zinc-200">{title}</p>
      <p className="text-base text-zinc-400 mt-1.5 max-w-md leading-relaxed">{description}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  )
}
