import { useLocation } from 'react-router-dom'
import ApiStatusIndicator from '../ui/ApiStatusIndicator'

const pageLabels: Record<string, { title: string; subtitle: string }> = {
  '/dashboard':    { title: 'Security Dashboard', subtitle: 'Overview of local posture & recent scans' },
  '/scan':         { title: 'New Security Scan', subtitle: 'Execute vulnerability assessment against authorized target' },
  '/scan-history': { title: 'Scan History', subtitle: 'Audit trail of past security assessments' },
  '/reports':      { title: 'Assessment Reports', subtitle: 'Detailed vulnerability findings & downloadable reports' },
  '/settings':     { title: 'Scanner Settings', subtitle: 'Target allowlist & scan configuration' },
}

export default function TopBar() {
  const { pathname } = useLocation()
  const page = pageLabels[pathname] ?? { title: 'VulnWatch', subtitle: 'Web Security Testing Platform' }

  return (
    <header className="flex items-center justify-between h-16 px-8 bg-surface-850 border-b border-surface-600/70 shrink-0">
      <div className="flex items-baseline gap-3.5">
        <h1 className="text-sm md:text-base font-semibold text-zinc-100 uppercase tracking-wider">{page.title}</h1>
        <span className="hidden md:inline text-xs md:text-sm text-zinc-400 font-normal">| {page.subtitle}</span>
      </div>
      <ApiStatusIndicator />
    </header>
  )
}
