interface PlaceholderBannerProps {
  message?: string
}

/**
 * PlaceholderBanner — notice for placeholder sections.
 */
export default function PlaceholderBanner({
  message = 'This section is currently configured with placeholder settings.',
}: PlaceholderBannerProps) {
  return (
    <div className="flex items-start gap-3.5 p-4 rounded-lg bg-yellow-950/30 border border-yellow-700/50 mb-6 text-sm md:text-base">
      <span className="text-yellow-400 text-lg shrink-0">⚠</span>
      <div>
        <p className="font-semibold text-yellow-300 uppercase tracking-wide text-xs mb-1">
          Placeholder Setting
        </p>
        <p className="text-yellow-200/80 leading-normal">{message}</p>
      </div>
    </div>
  )
}
