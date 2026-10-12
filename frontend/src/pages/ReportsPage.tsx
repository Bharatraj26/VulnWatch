import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  FileText,
  Eye,
  ChevronRight,
  AlertCircle,
  RefreshCw,
  Download,
  FileCode,
  ShieldAlert,
  ArrowLeft,
  CheckCircle2,
  Clock,
  Target,
  FileSpreadsheet,
} from 'lucide-react'
import PageHeader from '../components/ui/PageHeader'
import StatusBadge from '../components/ui/StatusBadge'
import SeverityBadge from '../components/ui/SeverityBadge'
import SeverityBar from '../components/ui/SeverityBar'
import ScoreRing from '../components/ui/ScoreRing'
import EmptyState from '../components/ui/EmptyState'
import LoadingState from '../components/ui/LoadingState'
import { apiClient } from '../lib/apiClient'
import { formatDateTime } from '../lib/utils'
import type { Report, ReportDetail } from '../types'

function getGrade(score: number): { grade: string; color: string } {
  if (score >= 90) return { grade: 'A', color: 'text-emerald-400 border-emerald-800/80 bg-emerald-950/40' }
  if (score >= 75) return { grade: 'B', color: 'text-cyan-400 border-cyan-800/80 bg-cyan-950/40' }
  if (score >= 60) return { grade: 'C', color: 'text-amber-400 border-amber-800/80 bg-amber-950/40' }
  if (score >= 40) return { grade: 'D', color: 'text-orange-400 border-orange-800/80 bg-orange-950/40' }
  return { grade: 'F', color: 'text-red-400 border-red-800/80 bg-red-950/40' }
}

export default function ReportsPage() {
  const [searchParams] = useSearchParams()
  const initialScanId = searchParams.get('scanId')

  const [reports, setReports] = useState<Report[]>([])
  const [selectedReport, setSelectedReport] = useState<ReportDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadingDetail, setLoadingDetail] = useState(false)
  const [downloadingId, setDownloadingId] = useState<string | null>(null)
  const [downloadingFormat, setDownloadingFormat] = useState<'pdf' | 'json' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null)

  async function loadReports(targetScanId?: string | null) {
    setLoading(true)
    setError(null)
    try {
      const data = await apiClient.listReports()
      setReports(data)

      const toLoad = targetScanId || initialScanId
      if (toLoad) {
        await loadReportDetail(toLoad)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to retrieve reports from server.')
    } finally {
      setLoading(false)
    }
  }

  async function loadReportDetail(idOrScanId: string) {
    setLoadingDetail(true)
    setError(null)
    try {
      const detail = await apiClient.getReport(idOrScanId)
      setSelectedReport(detail)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load report details.')
    } finally {
      setLoadingDetail(false)
    }
  }

  async function handleDownload(reportId: string, format: 'pdf' | 'json') {
    setDownloadingId(reportId)
    setDownloadingFormat(format)
    setError(null)
    setDownloadSuccess(null)
    try {
      if (format === 'pdf') {
        await apiClient.downloadReportPdf(reportId)
        setDownloadSuccess(`Report ${reportId} (PDF) downloaded successfully.`)
      } else {
        await apiClient.downloadReportJson(reportId)
        setDownloadSuccess(`Report ${reportId} (JSON) exported successfully.`)
      }
      setTimeout(() => setDownloadSuccess(null), 5000)
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to download ${format.toUpperCase()} report.`)
    } finally {
      setDownloadingId(null)
      setDownloadingFormat(null)
    }
  }

  useEffect(() => {
    loadReports(initialScanId)
  }, [initialScanId])

  return (
    <div className="space-y-7">
      <PageHeader
        title="Security Reports"
        description="Comprehensive audit reports generated from passive local application scans."
        action={
          <button
            onClick={() => loadReports(null)}
            disabled={loading}
            className="btn-secondary"
            title="Refresh reports"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        }
      />

      {error && (
        <div className="flex items-start gap-3.5 p-4 rounded-lg bg-red-950/40 border border-red-700/60 text-sm text-red-200">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <p className="flex-1 leading-normal">{error}</p>
        </div>
      )}

      {downloadSuccess && (
        <div className="flex items-center gap-2.5 p-4 rounded-lg bg-emerald-950/40 border border-emerald-700/60 text-sm text-emerald-200">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          <p>{downloadSuccess}</p>
        </div>
      )}

      {loading ? (
        <LoadingState message="Loading security reports..." rows={5} />
      ) : selectedReport ? (
        /* ═════════════════════════════════════════════════════════════════════
           REPORT DETAIL VIEW
           ═════════════════════════════════════════════════════════════════════ */
        <div className="space-y-7">
          {/* Top navigation & action bar */}
          <div className="flex flex-wrap items-center justify-between gap-4">
            <button
              onClick={() => setSelectedReport(null)}
              className="btn-ghost"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Reports List
            </button>

            <div className="flex items-center gap-3">
              <button
                onClick={() => handleDownload(selectedReport.id, 'pdf')}
                disabled={downloadingId === selectedReport.id}
                className="btn-primary"
                title="Download complete PDF audit report"
              >
                <Download className="w-4 h-4" />
                {downloadingId === selectedReport.id && downloadingFormat === 'pdf'
                  ? 'Generating PDF...'
                  : 'Download PDF Report'}
              </button>

              <button
                onClick={() => handleDownload(selectedReport.id, 'json')}
                disabled={downloadingId === selectedReport.id}
                className="btn-secondary"
                title="Export raw JSON findings data"
              >
                <FileCode className="w-4 h-4" />
                {downloadingId === selectedReport.id && downloadingFormat === 'json'
                  ? 'Exporting...'
                  : 'Export JSON'}
              </button>
            </div>
          </div>

          {loadingDetail ? (
            <LoadingState message="Loading report detail..." rows={6} />
          ) : (
            <>
              {/* Report Summary Card */}
              <div className="card space-y-6">
                <div className="flex flex-col md:flex-row md:items-start justify-between gap-6 pb-6 border-b border-surface-600/60">
                  <div className="space-y-4 flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-3">
                      <FileText className="w-5 h-5 text-brand-400" />
                      <h2 className="text-xl md:text-2xl font-bold text-zinc-100 font-mono">
                        Report {selectedReport.id}
                      </h2>
                      <StatusBadge status={selectedReport.status} />
                      {(() => {
                        const gradeInfo = getGrade(selectedReport.securityScore)
                        return (
                          <span className={`inline-flex items-center px-3 py-1 text-sm font-mono font-semibold rounded border ${gradeInfo.color}`}>
                            Grade {gradeInfo.grade}
                          </span>
                        )
                      })()}
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-3">
                      <div className="flex items-center gap-2.5 text-sm md:text-base text-zinc-200">
                        <Target className="w-4 h-4 text-zinc-400 shrink-0" />
                        <span className="text-zinc-400 text-sm">Target:</span>
                        <span className="font-mono text-zinc-100 font-medium truncate">{selectedReport.target}</span>
                      </div>
                      <div className="flex items-center gap-2.5 text-sm md:text-base text-zinc-200">
                        <Clock className="w-4 h-4 text-zinc-400 shrink-0" />
                        <span className="text-zinc-400 text-sm">Scanned:</span>
                        <span className="font-mono text-zinc-200 text-sm">{formatDateTime(selectedReport.scannedAt)}</span>
                      </div>
                      <div className="flex items-center gap-2.5 text-sm md:text-base text-zinc-200">
                        <ShieldAlert className="w-4 h-4 text-zinc-400 shrink-0" />
                        <span className="text-zinc-400 text-sm">Scan ID:</span>
                        <span className="font-mono text-brand-400 font-medium text-sm">{selectedReport.scanId}</span>
                      </div>
                      <div className="flex items-center gap-2.5 text-sm md:text-base text-zinc-200">
                        <FileSpreadsheet className="w-4 h-4 text-zinc-400 shrink-0" />
                        <span className="text-zinc-400 text-sm">Total Findings:</span>
                        <span className="font-mono font-bold text-zinc-100">{selectedReport.findings}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-5 shrink-0 bg-surface-850 px-6 py-4 rounded-lg border border-surface-600/60">
                    <div className="text-right">
                      <p className="text-xs md:text-sm font-semibold text-zinc-400 uppercase tracking-wider">Security Score</p>
                      <p className="text-3xl font-bold font-mono text-zinc-100">{selectedReport.securityScore}<span className="text-sm text-zinc-400 font-normal">/100</span></p>
                    </div>
                    <ScoreRing score={selectedReport.securityScore} size={76} />
                  </div>
                </div>

                {/* Scoring Methodology Narrative */}
                <div className="pt-2">
                  <p className="text-xs md:text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-1.5">
                    Scoring Methodology
                  </p>
                  <p className="text-[15px] text-zinc-300 leading-relaxed font-sans">
                    Evaluated from a baseline score of 100 with deduction penalties: Critical (-25), High (-15), Medium (-8), Low (-3), and Info (0). Final score is bounded between 0 and 100.
                  </p>
                </div>

                {/* Executive Summary Narrative */}
                <div className="pt-2">
                  <p className="text-xs md:text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-2">
                    Executive Summary
                  </p>
                  <div className="bg-surface-850 p-4 rounded-md border border-surface-600/60 text-[15px] text-zinc-200 leading-relaxed font-sans">
                    {selectedReport.summary}
                  </div>
                </div>
              </div>

              {/* Severity Breakdown Card */}
              <div className="card space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-surface-600/60">
                  <h3 className="text-xl font-semibold text-zinc-100 uppercase tracking-wider">
                    Severity Distribution
                  </h3>
                  <span className="text-sm font-mono text-zinc-400">
                    {selectedReport.findings} Total Findings
                  </span>
                </div>
                <SeverityBar counts={selectedReport.severityBreakdown} />
              </div>

              {/* Detailed Findings List */}
              <div className="card space-y-5">
                <div className="pb-4 border-b border-surface-600/60">
                  <h3 className="text-xl font-semibold text-zinc-100 uppercase tracking-wider">
                    Identified Findings & Missing Controls ({selectedReport.findings_list.length})
                  </h3>
                  <p className="text-sm text-zinc-400 mt-1">
                    Expand findings to review technical evidence, classification, and remediation steps.
                  </p>
                </div>

                {selectedReport.findings_list.length === 0 ? (
                  <div className="py-12 text-center bg-surface-850 rounded-md border border-surface-600/40">
                    <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
                    <p className="text-base font-semibold text-zinc-100">No Weaknesses or Missing Controls Found</p>
                    <p className="text-sm text-zinc-400 mt-1">Target satisfied all evaluated defensive headers and transport criteria.</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {selectedReport.findings_list.map((finding) => {
                      const isVulnerability = finding.type === 'vulnerability'
                      return (
                        <details
                          key={finding.id}
                          className="group border border-surface-600/80 rounded-lg overflow-hidden bg-surface-850 transition-colors"
                        >
                          <summary className="flex items-center justify-between gap-4 p-4 hover:bg-surface-750 transition-colors cursor-pointer list-none select-none">
                            <div className="flex flex-wrap items-center gap-3 min-w-0">
                              <SeverityBadge severity={finding.severity} />
                              <span
                                className={`text-xs md:text-sm font-mono px-2.5 py-1 rounded border uppercase font-medium ${
                                  isVulnerability
                                    ? 'bg-red-950/40 text-red-300 border-red-800/60'
                                    : 'bg-zinc-800 text-zinc-200 border-zinc-700'
                                }`}
                              >
                                {isVulnerability ? 'Confirmed Vulnerability' : 'Missing Control'}
                              </span>
                              <span className="text-base md:text-[17px] font-semibold text-zinc-100 truncate">
                                {finding.title}
                              </span>
                            </div>
                            <ChevronRight className="w-5 h-5 text-zinc-400 shrink-0 group-open:rotate-90 transition-transform" />
                          </summary>

                          <div className="px-5 pt-4 pb-5 space-y-4 text-[15px] text-zinc-200 border-t border-surface-600/60 bg-surface-800">
                            {/* Metadata row */}
                            <div className="flex flex-wrap gap-6 text-sm text-zinc-400 pb-3 border-b border-surface-600/40">
                              {finding.category && (
                                <div>
                                  <span className="text-zinc-500 uppercase text-xs font-semibold">Category: </span>
                                  <span className="text-zinc-200 font-mono text-sm">{finding.category}</span>
                                </div>
                              )}
                              {finding.location && (
                                <div>
                                  <span className="text-zinc-500 uppercase text-xs font-semibold">Location: </span>
                                  <span className="font-mono text-zinc-200 bg-surface-750 px-2 py-0.5 rounded text-sm">
                                    {finding.location}
                                  </span>
                                </div>
                              )}
                            </div>

                            {/* Description */}
                            <div>
                              <p className="text-xs md:text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-1.5">
                                Description
                              </p>
                              <p className="leading-relaxed text-zinc-200 text-[15px]">{finding.description}</p>
                            </div>

                            {/* Evidence block */}
                            {finding.evidence && (
                              <div>
                                <p className="text-xs md:text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-1.5">
                                  Observed Evidence
                                </p>
                                <div className="code-block">
                                  <code>{finding.evidence}</code>
                                </div>
                              </div>
                            )}

                            {/* Remediation recommendation */}
                            <div className="bg-surface-850 p-4 rounded-md border border-emerald-800/40">
                              <p className="text-xs md:text-sm font-semibold text-emerald-400 uppercase tracking-wider mb-1.5">
                                Recommended Remediation
                              </p>
                              <p className="leading-relaxed text-zinc-100 text-[15px]">{finding.recommendation}</p>
                            </div>
                          </div>
                        </details>
                      )
                    })}
                  </div>
                )}
              </div>

              {/* Assessment Scope & Limitations Note */}
              <div className="p-4 rounded-lg border border-surface-600/60 bg-surface-850 text-xs md:text-sm text-zinc-400 leading-relaxed">
                <span className="font-semibold text-zinc-300 uppercase tracking-wider">Assessment Scope & Disclaimer: </span>
                This automated security report was produced by VulnWatch using passive HTTP transport, defensive header inspection, and local dependency audits against authorized test targets. It does not constitute a full penetration test and does not guarantee the absence of unassessed application vulnerabilities.
              </div>
            </>
          )}
        </div>
      ) : (
        /* ═════════════════════════════════════════════════════════════════════
           REPORTS LIST VIEW
           ═════════════════════════════════════════════════════════════════════ */
        <div className="table-container">
          {reports.length === 0 ? (
            <EmptyState
              title="No security reports found"
              description="Execute a scan against an authorized local target to generate your first audit report."
              icon={<FileText className="w-12 h-12" />}
            />
          ) : (
            <table className="w-full">
              <thead>
                <tr>
                  <th className="table-th">Report ID</th>
                  <th className="table-th">Target</th>
                  <th className="table-th">Scan Date</th>
                  <th className="table-th">Score</th>
                  <th className="table-th">Findings</th>
                  <th className="table-th">Status</th>
                  <th className="table-th text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-600/40">
                {reports.map((report) => (
                  <tr key={report.id} className="table-row">
                    <td className="table-td font-mono text-brand-400 font-semibold whitespace-nowrap text-sm">
                      {report.id}
                    </td>
                    <td className="table-td font-mono text-zinc-100 max-w-[220px] truncate text-base">
                      {report.target}
                    </td>
                    <td className="table-td text-zinc-400 whitespace-nowrap font-mono text-sm">
                      {formatDateTime(report.scannedAt)}
                    </td>
                    <td className="table-td whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-zinc-100 text-base">{report.securityScore}</span>
                        <span className="text-zinc-400 text-xs font-mono">/100</span>
                      </div>
                    </td>
                    <td className="table-td font-mono text-zinc-100 font-semibold whitespace-nowrap text-base">
                      {report.findings}
                    </td>
                    <td className="table-td whitespace-nowrap">
                      <StatusBadge status={report.status} />
                    </td>
                    <td className="table-td text-right whitespace-nowrap">
                      <div className="inline-flex items-center gap-2 justify-end">
                        <button
                          onClick={() => loadReportDetail(report.id)}
                          className="btn-ghost py-1.5 px-3 text-sm"
                          title="View detailed audit report"
                        >
                          <Eye className="w-4 h-4" />
                          View
                        </button>
                        <button
                          onClick={() => handleDownload(report.id, 'pdf')}
                          disabled={downloadingId === report.id}
                          className="btn-secondary py-1.5 px-3 text-sm"
                          title="Download PDF report"
                        >
                          <Download className="w-4 h-4 text-brand-400" />
                          PDF
                        </button>
                        <button
                          onClick={() => handleDownload(report.id, 'json')}
                          disabled={downloadingId === report.id}
                          className="btn-ghost py-1.5 px-3 text-sm text-zinc-400 hover:text-white"
                          title="Export JSON findings"
                        >
                          <FileCode className="w-4 h-4" />
                          JSON
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
