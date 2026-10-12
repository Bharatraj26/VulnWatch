import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  ScanLine,
  History,
  FileText,
  Settings,
  ShieldCheck,
} from 'lucide-react'

const navItems = [
  { to: '/dashboard',    label: 'Dashboard',     Icon: LayoutDashboard },
  { to: '/scan',         label: 'New Scan',       Icon: ScanLine        },
  { to: '/scan-history', label: 'Scan History',   Icon: History         },
  { to: '/reports',      label: 'Reports',        Icon: FileText        },
  { to: '/settings',     label: 'Settings',       Icon: Settings        },
]

export default function Sidebar() {
  return (
    <aside className="flex flex-col w-64 shrink-0 bg-surface-850 border-r border-surface-600/70 select-none">
      {/* ── Brand ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 px-5 py-5 border-b border-surface-600/70">
        <div className="flex items-center justify-center w-9 h-9 rounded-md bg-surface-750 border border-surface-600 shrink-0 text-brand-500">
          <ShieldCheck className="w-6 h-6" />
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-lg font-bold text-zinc-100 tracking-tight leading-none">VulnWatch</span>
            <span className="px-1.5 py-0.5 text-[10px] font-mono uppercase font-semibold bg-surface-700 text-zinc-300 border border-surface-600 rounded">
              v1.2
            </span>
          </div>
          <p className="text-xs text-zinc-400 mt-1">Security Testing Platform</p>
        </div>
      </div>

      {/* ── Nav (16px minimum links) ──────────────────────────────────────── */}
      <nav className="flex-1 px-3 py-5 space-y-1.5" aria-label="Main navigation">
        {navItems.map(({ to, label, Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3.5 py-2.5 rounded-md text-base font-medium transition-colors ${
                isActive
                  ? 'bg-surface-750 text-white border-l-4 border-brand-500 font-semibold pl-3'
                  : 'text-zinc-300 hover:text-white hover:bg-surface-800'
              }`
            }
          >
            <Icon className="w-5 h-5 shrink-0 text-zinc-400" aria-hidden="true" />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* ── Security Policy Footer ────────────────────────────────────────── */}
      <div className="p-4 mx-3 mb-4 rounded-md border border-surface-600/60 bg-surface-900/70">
        <div className="flex items-center justify-between text-xs font-semibold text-zinc-300 mb-1.5">
          <span className="uppercase tracking-wide">Target Policy</span>
          <span className="text-brand-400 font-mono text-xs">ENFORCED</span>
        </div>
        <p className="text-xs text-zinc-400 leading-relaxed">
          Restricted to authorized loopback & local test environments.
        </p>
      </div>
    </aside>
  )
}
