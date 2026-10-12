import { useState, useMemo, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Search, Filter, Eye, RefreshCw, AlertCircle, ScanLine, Download } from 'lucide-react'
import PageHeader from '../components/ui/PageHeader'
import SeverityBadge from '../components/ui/SeverityBadge'
import StatusBadge from '../components/ui/StatusBadge'
import EmptyState from '../components/ui/EmptyState'
import LoadingState from '../components/ui/LoadingState'
import { apiClient } from '../lib/apiClient'
import { formatDateTime, formatDuration } from '../lib/utils'
import type { Scan, ScanStatus, Severity } from '../types'

const SEVERITY_OPTIONS: Array<{ value: Severity | 'all'; label: string }> = [
  { value: 'all',      label: 'All Severities' },
  { value: 'critical', label: 'Critical'        },
  { value: 'high',     label: 'High'            },
  { value: 'medium',   label: 'Medium'          },
  { value: 'low',      label: 'Low'             },
  { value: 'info',     label: 'Info'            },
]

const STATUS_OPTIONS: Array<{ value: ScanStatus | 'all'; label: string }> = [
  { value: 'all',       label: 'All Statuses' },
  { value: 'completed', label: 'Completed'    },
  { value: 'failed',    label: 'Failed'       },
  { value: 'running',   label: 'Running'      },
  { value: 'queued',    label: 'Queued'       },
]

export default function ScanHistoryPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [downloadingId, setDownloadingId] = useState<string | null>(null)

  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState<Severity | 'all'>('all')
  const [status, setStatus] = useState<ScanStatus | 'all'>('all')

  async function loadScans() {
    setLoading(true)
    setError(null)
    try {
      const data = await apiClient.listScans()
      setScans(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to retrieve scan records.')
    } finally {
      setLoading(false)
    }
  }

  async function handleDownloadPdf(scanId: string) {
    setDownloadingId(scanId)
    setError(null)
    try {
      await apiClient.downloadReportPdf(scanId)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to download report PDF.')
    } finally {
      setDownloadingId(null)
    }
  }

  useEffect(() => {
    loadScans()
  }, [])

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return scans.filter(scan => {
      const matchSearch   = !q || scan.target.toLowerCase().includes(q) || scan.id.toLowerCase().includes(q)
      const matchSeverity = severity === 'all' || scan.severity === severity
      const matchStatus   = status   === 'all' || scan.status   === status
      return matchSearch && matchSeverity && matchStatus
    })
  }, [scans, search, severity, status])

  return (
    <div className="space-y-7">
      <PageHeader
        title="Scan History"
        description="Audit log of previous local security assessments stored in SQLite."
        action={
          <div className="flex items-center gap-3">
            <button
              onClick={loadScans}
              disabled={loading}
              className="btn-secondary"
              title="Refresh scans"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <Link to="/scan" className="btn-primary">
              <ScanLine className="w-4 h-4" />
              New Scan
            </Link>
          </div>
        }
      />

      {error && (
        <div className="flex items-start gap-3.5 p-4 rounded-lg bg-red-950/40 border border-red-700/60 text-sm text-red-200">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <p className="flex-1 leading-normal">{error}</p>
        </div>
      )}

      {/* ── Filters ────────────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-4">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px] max-w-md">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400 pointer-events-none" />
          <input
            type="search"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by target or scan ID…"
            className="input pl-10"
          />
        </div>

        {/* Severity filter */}
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-zinc-400 shrink-0" />
          <select
            value={severity}
            onChange={e => setSeverity(e.target.value as Severity | 'all')}
            className="input w-44 py-2"
            aria-label="Filter by severity"
          >
            {SEVERITY_OPTIONS.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

        {/* Status filter */}
        <div>
          <select
            value={status}
            onChange={e => setStatus(e.target.value as ScanStatus | 'all')}
            className="input w-44 py-2"
            aria-label="Filter by status"
          >
            {STATUS_OPTIONS.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

        {(search || severity !== 'all' || status !== 'all') && (
          <button
            onClick={() => { setSearch(''); setSeverity('all'); setStatus('all') }}
            className="btn-ghost text-sm py-1.5 px-3"
          >
            Reset Filters
          </button>
        )}
      </div>

      {/* ── Table ──────────────────────────────────────────────────────────── */}
      {loading ? (
        <LoadingState message="Loading scan records..." rows={6} />
      ) : (
        <div className="table-container">
          {filtered.length === 0 ? (
            <EmptyState
              title={scans.length === 0 ? 'No scans in database' : 'No scans match your filters'}
              description={
                scans.length === 0
                  ? 'Run a scan from the New Scan page to generate audit records.'
                  : 'Try adjusting your search criteria or resetting filters.'
              }
              icon={<ScanLine className="w-12 h-12" />}
              action={
                scans.length === 0 ? (
                  <Link to="/scan" className="btn-primary">
                    Start First Scan
                  </Link>
                ) : undefined
              }
            />
          ) : (
            <table className="w-full">
              <thead>
                <tr>
                  <th className="table-th">Scan ID</th>
                  <th className="table-th">Target</th>
                  <th className="table-th">Type</th>
                  <th className="table-th">Started</th>
                  <th className="table-th">Duration</th>
                  <th className="table-th">Findings</th>
                  <th className="table-th">Severity</th>
                  <th className="table-th">Status</th>
                  <th className="table-th text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-600/40">
                {filtered.map((scan) => (
                  <tr key={scan.id} className="table-row">
                    <td className="table-td font-mono text-brand-400 font-semibold whitespace-nowrap text-sm">
                      {scan.id}
                    </td>
                    <td className="table-td font-mono text-zinc-100 max-w-[220px] truncate text-base">
                      {scan.target}
                    </td>
                    <td className="table-td capitalize text-zinc-300 text-sm">
                      {scan.scanType}
                    </td>
                    <td className="table-td text-zinc-400 whitespace-nowrap font-mono text-sm">
                      {formatDateTime(scan.startedAt)}
                    </td>
                    <td className="table-td text-zinc-400 whitespace-nowrap font-mono text-sm">
                      {scan.duration != null ? formatDuration(scan.duration) : '—'}
                    </td>
                    <td className="table-td font-mono text-zinc-100 font-semibold whitespace-nowrap text-base">
                      {scan.findings}
                    </td>
                    <td className="table-td whitespace-nowrap">
                      <SeverityBadge severity={scan.severity} />
                    </td>
                    <td className="table-td whitespace-nowrap">
                      <StatusBadge status={scan.status} />
                    </td>
                    <td className="table-td text-right whitespace-nowrap">
                      <div className="inline-flex items-center gap-2 justify-end">
                        <Link
                          to={`/reports?scanId=${scan.id}`}
                          className="btn-ghost py-1.5 px-3 text-sm"
                          title="View detailed audit report"
                        >
                          <Eye className="w-4 h-4" />
                          Report
                        </Link>
                        <button
                          onClick={() => handleDownloadPdf(scan.id)}
                          disabled={downloadingId === scan.id}
                          className="btn-secondary py-1.5 px-3 text-sm"
                          title="Download PDF report directly"
                        >
                          <Download className="w-4 h-4 text-brand-400" />
                          PDF
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}
