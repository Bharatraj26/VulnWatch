import { useEffect, useState } from 'react'
import { apiClient, type HealthResponse } from '../../lib/apiClient'

type Status = 'loading' | 'ok' | 'error'

/**
 * ApiStatusIndicator
 * ------------------
 * Calls GET /api/health on mount and shows an engine status indicator.
 * Refreshes every 30 seconds.
 */
export default function ApiStatusIndicator() {
  const [status, setStatus] = useState<Status>('loading')
  const [data, setData] = useState<HealthResponse | null>(null)

  const checkHealth = async () => {
    try {
      const result = await apiClient.getHealth()
      setData(result)
      setStatus('ok')
    } catch {
      setStatus('error')
      setData(null)
    }
  }

  useEffect(() => {
    checkHealth()
    const interval = setInterval(checkHealth, 30_000)
    return () => clearInterval(interval)
  }, [])

  const dotClass =
    status === 'ok'
      ? 'bg-brand-500 ring-2 ring-brand-500/20'
      : status === 'error'
        ? 'bg-red-500 ring-2 ring-red-500/20'
        : 'bg-zinc-500 animate-pulse'

  const label =
    status === 'ok'
      ? `${data?.service ?? 'Engine'} Active`
      : status === 'error'
        ? 'Engine Offline'
        : 'Connecting...'

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded border border-surface-600/70 bg-surface-850 text-xs md:text-sm text-zinc-300 font-mono">
      <span
        className={`inline-block w-2 h-2 rounded-full shrink-0 ${dotClass}`}
        title="Engine status"
      />
      <span className="truncate">{label}</span>
    </div>
  )
}
