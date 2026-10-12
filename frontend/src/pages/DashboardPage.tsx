import { useState, useEffect } from 'react'
import { Activity, Bug, AlertTriangle, Clock, ScanLine, ExternalLink, RefreshCw, AlertCircle } from 'lucide-react'
import { Link } from 'react-router-dom'
import StatCard from '../components/ui/StatCard'
import PageHeader from '../components/ui/PageHeader'
import SeverityBadge from '../components/ui/SeverityBadge'
import StatusBadge from '../components/ui/StatusBadge'
import SeverityBar from '../components/ui/SeverityBar'
import EmptyState from '../components/ui/EmptyState'
import LoadingState from '../components/ui/LoadingState'
import { apiClient } from '../lib/apiClient'
import type { StatsResponse } from '../lib/apiClient'
import type { Scan, SeverityCount } from '../types'
import { formatDate } from '../lib/utils'

export default function DashboardPage() {
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [recentScans, setRecentScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  async function loadDashboardData() {
    setLoading(true)
    setError(null)
    try {
      const [statsData, scansData] = await Promise.all([
        apiClient.getStats(),
        apiClient.listScans(),
      ])
      setStats(statsData)
      setRecentScans(scansData.slice(0, 5))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to connect to VulnWatch backend.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadDashboardData()
  }, [])

  const emptySeverityTotals: SeverityCount = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  const severityTotals = stats?.severityTotals || emptySeverityTotals

  const lastScanLabel = stats?.lastScan
    ? formatDate(stats.lastScan)
    : 'None'

  return (
    <div className="space-y-8">
      <PageHeader
        title="Security Dashboard"
        description="Monitor local security posture, scan activity, and vulnerability distributions."
        action={
          <div className="flex items-center gap-3">
            <button
              onClick={loadDashboardData}
              disabled={loading}
              className="btn-secondary"
              title="Refresh dashboard data"
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
          <div className="flex-1">
            <p className="font-semibold text-red-100 text-base">Backend Connection Error</p>
            <p className="mt-1 text-red-300 leading-normal">{error}</p>
          </div>
          <button
            onClick={loadDashboardData}
            className="text-sm font-semibold text-red-400 hover:text-white underline ml-3"
          >
            Retry
          </button>
        </div>
      )}

      {loading ? (
        <LoadingState message="Loading dashboard statistics..." rows={5} />
      ) : (
        <>
          {/* ── KPI Stat Cards ─────────────────────────────────────────────── */}
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5">
            <StatCard
              title="Total Scans"
              value={stats?.totalScans ?? 0}
              subtitle={stats && stats.totalScans > 0 ? 'Recorded in local database' : 'No scans executed yet'}
              icon={<Activity className="w-6 h-6" />}
              accentColor="text-zinc-100"
              isPlaceholder={false}
            />
            <StatCard
              title="Findings Identified"
              value={stats?.vulnerabilitiesFound ?? 0}
              subtitle="Missing controls & weaknesses"
              icon={<Bug className="w-6 h-6" />}
              accentColor="text-amber-400"
              isPlaceholder={false}
            />
            <StatCard
              title="Critical Issues"
              value={stats?.criticalIssues ?? 0}
              subtitle={stats && stats.criticalIssues > 0 ? 'Requires immediate remediation' : 'No critical findings'}
              icon={<AlertTriangle className="w-6 h-6" />}
              accentColor={stats && stats.criticalIssues > 0 ? 'text-red-400' : 'text-emerald-400'}
              isPlaceholder={false}
            />
            <StatCard
              title="Last Scan"
              value={lastScanLabel}
              subtitle={stats?.lastScanTarget || 'No prior scans'}
              icon={<Clock className="w-6 h-6" />}
              accentColor="text-zinc-200"
              isPlaceholder={false}
            />
          </div>

          {/* ── Lower section: recent scans + severity chart ──────────────────── */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* Recent Scans Table — 2/3 width */}
            <div className="lg:col-span-2 card space-y-5">
              <div className="flex items-center justify-between pb-4 border-b border-surface-600/60">
                <div>
                  <h3 className="text-xl font-semibold text-zinc-100 uppercase tracking-wider">Recent Scans</h3>
                  <p className="text-sm text-zinc-400 mt-1">Most recent assessments against authorized targets</p>
                </div>
                {recentScans.length > 0 && (
                  <Link
                    to="/scan-history"
                    className="text-sm font-medium text-brand-400 hover:text-brand-300 flex items-center gap-1.5 transition-colors"
                  >
                    View all ({stats?.totalScans ?? 0}) <ExternalLink className="w-4 h-4" />
                  </Link>
                )}
              </div>

              {recentScans.length === 0 ? (
                <EmptyState
                  title="No scan records found"
                  description="Start your first security check against an authorized local application."
                  icon={<ScanLine className="w-10 h-10" />}
                  action={
                    <Link to="/scan" className="btn-primary">
                      Launch First Scan
                    </Link>
                  }
                />
              ) : (
                <div className="table-container border-0 bg-transparent">
                  <table className="w-full">
                    <thead>
                      <tr>
                        <th className="table-th">Target</th>
                        <th className="table-th">Date</th>
                        <th className="table-th">Findings</th>
                        <th className="table-th">Severity</th>
                        <th className="table-th">Status</th>
                        <th className="table-th text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-surface-600/40">
                      {recentScans.map((scan) => (
                        <tr key={scan.id} className="table-row">
                          <td className="table-td">
                            <span className="font-mono text-base font-medium text-zinc-100 truncate block max-w-[200px]">{scan.target}</span>
                            <span className="text-sm font-mono text-zinc-400">{scan.id}</span>
                          </td>
                          <td className="table-td text-zinc-400 whitespace-nowrap font-mono text-sm">{formatDate(scan.startedAt)}</td>
                          <td className="table-td font-mono text-base text-zinc-100 font-semibold">{scan.findings}</td>
                          <td className="table-td">
                            <SeverityBadge severity={scan.severity} />
                          </td>
                          <td className="table-td">
                            <StatusBadge status={scan.status} />
                          </td>
                          <td className="table-td text-right">
                            <Link
                              to={`/reports?scanId=${scan.id}`}
                              className="text-brand-400 hover:text-brand-300 transition-colors font-medium text-sm inline-flex items-center gap-1"
                            >
                              View Report →
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Severity Distribution — 1/3 width */}
            <div className="card space-y-5">
              <div className="pb-4 border-b border-surface-600/60">
                <h3 className="text-xl font-semibold text-zinc-100 uppercase tracking-wider">Severity Distribution</h3>
                <p className="text-sm text-zinc-400 mt-1">Aggregated findings across all scans</p>
              </div>
              <SeverityBar counts={severityTotals} />
              <div className="pt-4 border-t border-surface-600/60">
                <p className="text-sm text-zinc-400 text-center font-mono">
                  Total findings tracked: {Object.values(severityTotals).reduce((a, b) => a + b, 0)}
                </p>
              </div>
            </div>

          </div>
        </>
      )}
    </div>
  )
}
