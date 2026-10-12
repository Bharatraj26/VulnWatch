import { useState, useEffect } from 'react'
import { Settings, ScanLine, Palette, Server, CheckCircle, XCircle, Loader, ShieldAlert } from 'lucide-react'
import PageHeader from '../components/ui/PageHeader'
import { apiClient } from '../lib/apiClient'
import type { HealthResponse } from '../lib/apiClient'

type ApiStatus = 'idle' | 'checking' | 'ok' | 'error'

interface SettingSection {
  id: string
  label: string
  icon: React.ReactNode
}

const SECTIONS: SettingSection[] = [
  { id: 'application', label: 'Application',      icon: <Settings className="w-5 h-5" /> },
  { id: 'scan',        label: 'Scan Preferences', icon: <ScanLine className="w-5 h-5" /> },
  { id: 'appearance',  label: 'Appearance',       icon: <Palette className="w-5 h-5" /> },
  { id: 'api',         label: 'Engine & API',     icon: <Server className="w-5 h-5" /> },
]

export default function SettingsPage() {
  const [activeSection, setActiveSection] = useState('application')
  const [apiStatus, setApiStatus]         = useState<ApiStatus>('idle')
  const [apiData,   setApiData]           = useState<HealthResponse | null>(null)
  const [apiError,  setApiError]          = useState('')

  const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000 (proxy)'

  useEffect(() => {
    if (activeSection === 'api' && apiStatus === 'idle') {
      checkApi()
    }
  }, [activeSection])

  async function checkApi() {
    setApiStatus('checking')
    setApiError('')
    try {
      const data = await apiClient.getHealth()
      setApiData(data)
      setApiStatus('ok')
    } catch (err) {
      setApiError(err instanceof Error ? err.message : 'Unknown error')
      setApiStatus('error')
    }
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Scanner Settings"
        description="Review security policy, engine configurations, and local system environment."
      />

      <div className="flex flex-col md:flex-row gap-6">

        {/* ── Section Nav ─────────────────────────────────────────────────── */}
        <aside className="w-full md:w-60 shrink-0">
          <nav className="space-y-1.5">
            {SECTIONS.map(section => (
              <button
                key={section.id}
                onClick={() => setActiveSection(section.id)}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-md text-base font-medium transition-colors text-left ${
                  activeSection === section.id
                    ? 'bg-surface-750 text-white border-l-4 border-brand-500 pl-3 font-semibold'
                    : 'text-zinc-400 hover:text-white hover:bg-surface-800'
                }`}
              >
                <span className={activeSection === section.id ? 'text-brand-400' : 'text-zinc-400'}>
                  {section.icon}
                </span>
                {section.label}
              </button>
            ))}
          </nav>
        </aside>

        {/* ── Section Content ──────────────────────────────────────────────── */}
        <div className="flex-1 card min-h-[420px]">

          {/* Application Settings */}
          {activeSection === 'application' && (
            <SectionContent title="Application Details" icon={<Settings className="w-5 h-5 text-brand-400" />}>
              <SettingRow label="Platform Name" value="VulnWatch" />
              <SettingRow label="Version" value="v1.2.0 (Phase 4A Architecture)" />
              <SettingRow label="Backend Framework" value="Python + Flask (Windows Native)" />
              <SettingRow label="Data Storage" value="SQLite (local file: vulnwatch.db)" />
              <SettingRow label="Report Engine" value="ReportLab 5.0 (Offline PDF Generator)" />
            </SectionContent>
          )}

          {/* Scan Preferences */}
          {activeSection === 'scan' && (
            <SectionContent title="Scan Preferences & Policy" icon={<ScanLine className="w-5 h-5 text-brand-400" />}>
              <SettingRow label="Default Scan Type" value="Basic Security Check" />
              <SettingRow label="Scan Timeout (seconds)" value="15" />
              <SettingRow label="Concurrent Scans" value="1 (Sequential execution)" />
              <SettingRow label="Target Enforcement" value="Strict Server-Side SSRF Protection" />
              <SettingRow label="Authorized Hosts" value="localhost, 127.0.0.1, ::1" />

              <div className="mt-5 p-4 rounded-lg bg-surface-850 border border-surface-600/70 text-sm">
                <div className="flex items-center gap-2.5 text-zinc-200 font-semibold mb-1.5 text-base">
                  <ShieldAlert className="w-5 h-5 text-brand-400" />
                  Target Authorization & Safe Scanning Guarantee
                </div>
                <p className="text-zinc-400 leading-relaxed text-sm">
                  VulnWatch is strictly bounded to authorized local loopback destinations.
                  External IPs, cloud metadata endpoints (169.254.169.254), internal private ranges (RFC 1918), and third-party hostnames are blocked at both validation and socket resolution layers.
                </p>
              </div>
            </SectionContent>
          )}

          {/* Appearance */}
          {activeSection === 'appearance' && (
            <SectionContent title="Appearance & Design System" icon={<Palette className="w-5 h-5 text-brand-400" />}>
              <SettingRow label="Theme" value="Graphite Security Console (#121316)" />
              <SettingRow label="Primary Font" value="IBM Plex Sans (Bundled locally)" />
              <SettingRow label="Monospace Font" value="IBM Plex Mono (Bundled locally)" />
              <SettingRow label="Accent Palette" value="Emerald #10b981 / Accessible Severity Indicators" />
              <SettingRow label="Containerization" value="None (Direct Windows native execution)" />
            </SectionContent>
          )}

          {/* API Configuration */}
          {activeSection === 'api' && (
            <SectionContent title="API & Backend Health" icon={<Server className="w-5 h-5 text-brand-400" />}>
              <SettingRow label="Backend API URL" value={apiBaseUrl} />
              <SettingRow label="API Protocol" value="HTTP REST (v1 endpoints)" />
              <SettingRow label="Report Formats" value="PDF (Binary application/pdf), JSON (application/json)" />

              {/* Live health check */}
              <div className="mt-5 pt-5 border-t border-surface-600/60">
                <div className="flex items-center justify-between mb-3.5">
                  <p className="text-base font-medium text-zinc-200">Backend Connection Status</p>
                  <button
                    onClick={checkApi}
                    disabled={apiStatus === 'checking'}
                    className="btn-secondary text-sm py-1.5 px-3"
                  >
                    {apiStatus === 'checking' && (
                      <Loader className="w-4 h-4 animate-spin" />
                    )}
                    {apiStatus === 'checking' ? 'Checking…' : 'Check Now'}
                  </button>
                </div>

                <div className="p-4 rounded-lg bg-surface-850 border border-surface-600/60 space-y-2.5">
                  {apiStatus === 'idle' && (
                    <p className="text-sm text-zinc-400">Click "Check Now" to test backend reachability.</p>
                  )}
                  {apiStatus === 'checking' && (
                    <p className="text-sm text-zinc-300 flex items-center gap-2">
                      <Loader className="w-4 h-4 animate-spin text-brand-400" />
                      Contacting Flask backend at {apiBaseUrl}…
                    </p>
                  )}
                  {apiStatus === 'ok' && apiData && (
                    <div className="space-y-2">
                      <p className="text-base text-emerald-400 flex items-center gap-2 font-medium">
                        <CheckCircle className="w-4 h-4" />
                        Backend Online & Healthy
                      </p>
                      <div className="text-sm font-mono text-zinc-300 space-y-1">
                        <p>Service: <span className="text-zinc-100 font-semibold">{apiData.service}</span></p>
                        <p>Status: <span className="text-emerald-400">{apiData.status}</span></p>
                      </div>
                    </div>
                  )}
                  {apiStatus === 'error' && (
                    <div className="space-y-2">
                      <p className="text-base text-red-400 flex items-center gap-2 font-medium">
                        <XCircle className="w-4 h-4" />
                        Connection Failed
                      </p>
                      <p className="text-sm font-mono text-red-400/90">{apiError}</p>
                      <p className="text-sm text-zinc-400">
                        Ensure backend is running: <span className="font-mono text-zinc-300">python run.py</span>
                      </p>
                    </div>
                  )}
                </div>

                <div className="mt-3 text-xs md:text-sm text-zinc-400 font-mono">
                  Endpoint: GET /api/health
                </div>
              </div>
            </SectionContent>
          )}

        </div>
      </div>
    </div>
  )
}

function SectionContent({
  title,
  icon,
  children,
}: {
  title: string
  icon: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div>
      <div className="flex items-center gap-2.5 mb-5 pb-4 border-b border-surface-600/60">
        {icon}
        <h3 className="text-xl font-semibold text-zinc-100 uppercase tracking-wider">{title}</h3>
      </div>
      <div className="space-y-3">{children}</div>
    </div>
  )
}

function SettingRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2.5 border-b border-surface-600/40 last:border-0">
      <label className="text-base text-zinc-400 shrink-0 w-48 md:w-56">{label}</label>
      <span className="text-base text-zinc-100 font-mono text-right">{value}</span>
    </div>
  )
}
