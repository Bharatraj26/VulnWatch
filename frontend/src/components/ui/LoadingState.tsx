interface LoadingStateProps {
  message?: string
  rows?: number
}

/**
 * LoadingState — skeleton shimmer shown while data is being fetched.
 */
export default function LoadingState({
  message = 'Loading…',
  rows = 4,
}: LoadingStateProps) {
  return (
    <div role="status" aria-label={message} className="space-y-3.5 animate-pulse">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-12 bg-surface-750/70 border border-surface-600/40 rounded-md" />
      ))}
      <span className="sr-only">{message}</span>
    </div>
  )
}
