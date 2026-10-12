import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ScanLine, ShieldCheck, AlertCircle, Info, Loader2, CheckCircle2, ArrowRight, Download, Cookie } from 'lucide-react'
import PageHeader from '../components/ui/PageHeader'
import ScoreRing from '../components/ui/ScoreRing'
import SeverityBadge from '../components/ui/SeverityBadge'
import { apiClient } from '../lib/apiClient'
import type { CreateScanResponse } from '../lib/apiClient'
import type { ScanType, Severity } from '../types'

interface ScanTypeOption {
  value: ScanType
  label: string
  description: string
  icon: React.ReactNode
}

const SCAN_TYPE_OPTIONS: ScanTypeOption[] = [
  {
    value: 'basic',
    label: 'Basic Security Check',
    description: 'Quick evaluation of transport encryption (HTTPS) and core defensive headers (CSP, XFO, XCTO).',
    icon: <ShieldCheck className="w-5 h-5" />,
  },
  {
    value: 'headers',
    label: 'Header Analysis',
    description: 'Comprehensive analysis of all HTTP response security headers and server version disclosure.',
    icon: <ScanLine className="w-5 h-5" />,
  },
  {
    value: 'cookies',
    label: 'Cookie Security',
    description: 'Inspects Set-Cookie headers for Secure, HttpOnly, and SameSite defensive flags.',
    icon: <Cookie className="w-5 h-5" />,
  },
  {
    value: 'full',
    label: 'Full Local Scan',
    description: 'Passive audit across transport, all security headers, cookies, server configuration, and project dependencies.',
    icon: <ScanLine className="w-5 h-5" />,
  },
]

export default function ScanPage() {
  const [targetUrl, setTargetUrl] = useState('http://localhost:8000')
  const [scanType, setScanType] = useState<ScanType>('basic')
  const [urlError, setUrlError] = useState('')
  const [isScanning, setIsScanning] = useState(false)
  const [scanResult, setScanResult] = useState<CreateScanResponse | null>(null)
  const [scanError, setScanError] = useState<string | null>(null)
  const [downloadingPdf, setDownloadingPdf] = useState(false)

  function validateUrl(value: string): boolean {
    try {
      const parsed = new URL(value)
      const allowedHosts = ['localhost', '127.0.0.1', '::1']
      if (!allowedHosts.some(h => parsed.hostname === h)) {
        setUrlError('Scanning is strictly restricted to local loopback targets (localhost / 127.0.0.1).')
        return false
      }
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        setUrlError('Only HTTP and HTTPS protocols are supported.')
        return false
      }
      setUrlError('')
      return true
    } catch {
      setUrlError('Please enter a valid URL (e.g. http://localhost:8000).')
      return false
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!validateUrl(targetUrl)) return

    setIsScanning(true)
    setScanError(null)
    setScanResult(null)

    try {
      const result = await apiClient.createScan({
        target_url: targetUrl,
        scan_type: scanType,
      })
      setScanResult(result)
    } catch (err) {
      setScanError(err instanceof Error ? err.message : 'Scan execution failed.')
    } finally {
      setIsScanning(false)
    }
  }

  async function handleDownloadReportPdf(reportId: string) {
    setDownloadingPdf(true)
    try {
      await apiClient.downloadReportPdf(reportId)
    } catch (err) {
      setScanError(err instanceof Error ? err.message : 'Failed to download PDF report.')
    } finally {
      setDownloadingPdf(false)
    }
  }

  function handleReset() {
    setScanResult(null)
    setScanError(null)
    setUrlError('')
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="New Security Scan"
        description="Launch an automated passive security assessment against an authorized local target."
      />

      {/* Safety Policy Notice */}
      <div className="flex items-start gap-3.5 p-5 rounded-lg bg-surface-850 border border-surface-600/70 text-sm md:text-[15px] text-zinc-300">
        <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-zinc-100">Target Authorization Policy: </span>
          <span className="text-zinc-400 leading-relaxed">
            VulnWatch conducts safe, passive security checks (inspecting HTTP transport, defensive response headers,
            and cookie attributes). Scanning is strictly restricted to local loopback targets (<code className="font-mono text-zinc-200">localhost</code> / <code className="font-mono text-zinc-200">127.0.0.1</code>).
            External and third-party network scanning is strictly prohibited by server-side policy.
          </span>
        </div>
      </div>

      {scanResult ? (
        /* ── Scan Completed State ─────────────────────────────────────────── */
        <div className="card max-w-3xl border-surface-600/80 bg-surface-800 space-y-7">
          <div className="flex items-start justify-between gap-5 pb-5 border-b border-surface-600/60">
            <div className="flex items-center gap-3.5">
              <CheckCircle2 className="w-7 h-7 text-brand-500 shrink-0" />
              <div>
                <h3 className="text-xl font-bold text-zinc-100">Assessment Completed</h3>
                <p className="text-sm text-zinc-400 mt-1">Target: <span className="font-mono text-zinc-200 text-sm">{scanResult.target}</span></p>
              </div>
            </div>
            <ScoreRing score={scanResult.score} size={76} />
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 bg-surface-850 rounded-md border border-surface-600/60">
              <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Scan ID</p>
              <p className="text-sm font-mono font-semibold text-brand-400 mt-1">{scanResult.id}</p>
            </div>
            <div className="p-4 bg-surface-850 rounded-md border border-surface-600/60">
              <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Duration</p>
              <p className="text-sm font-mono text-zinc-200 mt-1">{scanResult.duration}s</p>
            </div>
            <div className="p-4 bg-surface-850 rounded-md border border-surface-600/60">
              <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Findings</p>
              <p className="text-sm font-mono font-semibold text-amber-400 mt-1">{scanResult.findings}</p>
            </div>
            <div className="p-4 bg-surface-850 rounded-md border border-surface-600/60">
              <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Worst Severity</p>
              <div className="mt-1">
                <SeverityBadge severity={scanResult.severity as Severity} />
              </div>
            </div>
          </div>

          <p className="text-[15px] text-zinc-200 bg-surface-850 p-4 rounded-md border border-surface-600/60 leading-relaxed font-sans">
            {scanResult.message} Detailed findings, observations, and remediation guidance have been recorded in the SQLite database.
          </p>

          <div className="flex flex-wrap items-center gap-3.5 pt-5 border-t border-surface-600/60">
            <Link
              to={`/reports?scanId=${scanResult.id}`}
              className="btn-primary"
            >
              View Full Report <ArrowRight className="w-4 h-4" />
            </Link>

            <button
              onClick={() => handleDownloadReportPdf(scanResult.reportId || scanResult.id)}
              disabled={downloadingPdf}
              className="btn-secondary"
            >
              <Download className="w-4 h-4 text-brand-400" />
              {downloadingPdf ? 'Downloading PDF...' : 'Download PDF Report'}
            </button>

            <button
              onClick={handleReset}
              className="btn-ghost ml-auto"
            >
              New Scan
            </button>
          </div>
        </div>
      ) : (
        /* ── Scan Form ────────────────────────────────────────────────────── */
        <form onSubmit={handleSubmit} className="card max-w-3xl space-y-6" noValidate>

          {scanError && (
            <div className="flex items-start gap-3.5 p-4 rounded-lg bg-red-950/40 border border-red-700/60 text-sm text-red-200">
              <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-red-100 text-base">Scan Failed</p>
                <p className="mt-1 text-red-300 leading-normal">{scanError}</p>
              </div>
            </div>
          )}

          {/* Target URL */}
          <div>
            <label htmlFor="target-url" className="label">
              Target URL <span className="text-red-400">*</span>
            </label>
            <input
              id="target-url"
              type="url"
              value={targetUrl}
              disabled={isScanning}
              onChange={e => { setTargetUrl(e.target.value); setUrlError('') }}
              placeholder="http://localhost:8000"
              required
              className={`input input-mono ${urlError ? 'input-error' : ''}`}
            />
            {urlError ? (
              <p className="text-sm text-red-400 mt-1.5 flex items-center gap-1.5 font-medium">
                <AlertCircle className="w-4 h-4" />{urlError}
              </p>
            ) : (
              <p className="text-xs md:text-sm text-zinc-400 mt-1.5">
                Accepts local applications running on localhost or 127.0.0.1 (e.g. http://localhost:8000).
              </p>
            )}
          </div>

          {/* Scan Type */}
          <div>
            <p className="label">Scan Type</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              {SCAN_TYPE_OPTIONS.map(option => {
                const isSelected = scanType === option.value
                return (
                  <button
                    key={option.value}
                    type="button"
                    disabled={isScanning}
                    onClick={() => setScanType(option.value)}
                    className={`text-left p-4 rounded-lg border transition-colors ${
                      isSelected
                        ? 'border-brand-500 bg-surface-750 text-white shadow-sm'
                        : 'border-surface-600/80 bg-surface-850 text-zinc-400 hover:border-surface-500 hover:text-zinc-200'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 mb-2">
                      <span className={isSelected ? 'text-brand-400' : 'text-zinc-400'}>
                        {option.icon}
                      </span>
                      <span className="text-base font-semibold text-zinc-100">{option.label}</span>
                    </div>
                    <p className="text-xs md:text-sm leading-relaxed text-zinc-400">{option.description}</p>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Submit */}
          <div className="flex items-center gap-4 pt-4 border-t border-surface-600/60">
            <button
              type="submit"
              disabled={isScanning || !targetUrl}
              className="btn-primary"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Scanning Target…
                </>
              ) : (
                <>
                  <ScanLine className="w-4 h-4" />
                  Start Security Scan
                </>
              )}
            </button>
            <span className="text-xs md:text-sm text-zinc-400">
              {isScanning ? 'Executing passive HTTP checks...' : 'Safe passive checks only.'}
            </span>
          </div>

        </form>
      )}
    </div>
  )
}
