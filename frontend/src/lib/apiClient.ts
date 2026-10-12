/**
 * VulnWatch API Client
 * =====================
 * Typed wrapper around fetch for VulnWatch REST endpoints.
 *
 * During development, Vite proxies `/api/*` → `http://localhost:8000/api/*`.
 * In production or standalone mode, `VITE_API_URL` or `VITE_API_BASE_URL` is used.
 */

import type { Scan, ScanCreatePayload, Report, ReportDetail, SeverityCount } from '../types'

const BASE_URL = import.meta.env.VITE_API_URL ?? import.meta.env.VITE_API_BASE_URL ?? ''

type RequestOptions = Omit<RequestInit, 'body'> & {
  body?: unknown
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { body, ...rest } = options

  const response = await fetch(`${BASE_URL}${path}`, {
    ...rest,
    headers: {
      'Content-Type': 'application/json',
      ...rest.headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })

  if (!response.ok) {
    let errorDetail = `API error ${response.status}`
    try {
      const errJson = await response.json()
      if (errJson && errJson.detail) {
        errorDetail = errJson.detail
      }
    } catch {
      const text = await response.text()
      if (text) errorDetail = text
    }
    throw new Error(errorDetail)
  }

  return response.json() as Promise<T>
}

async function downloadFile(
  path: string,
  defaultFilename: string,
  expectedMimeType?: string,
): Promise<void> {
  const response = await fetch(`${BASE_URL}${path}`, {
    method: 'GET',
  })

  if (!response.ok) {
    let errorDetail = `Download failed (${response.status})`
    try {
      const errJson = await response.json()
      if (errJson && errJson.detail) {
        errorDetail = errJson.detail
      }
    } catch {
      const text = await response.text()
      if (text) errorDetail = text
    }
    throw new Error(errorDetail)
  }

  // Verify Content-Type matches expected type (prevents saving HTML/JSON errors as .pdf)
  const contentType = (response.headers.get('content-type') || '').toLowerCase()
  if (expectedMimeType && !contentType.includes(expectedMimeType.toLowerCase())) {
    let detailMsg = `Unexpected response type (${contentType}) from server.`
    try {
      const bodyText = await response.text()
      if (bodyText.startsWith('{')) {
        const parsed = JSON.parse(bodyText)
        if (parsed.detail) detailMsg = parsed.detail
      } else if (bodyText.includes('<html') || bodyText.includes('<!doctype')) {
        detailMsg = 'Server returned an HTML page instead of binary report content.'
      }
    } catch {
      // fallback to default detailMsg
    }
    throw new Error(detailMsg)
  }

  const blob = await response.blob()

  // Guard against empty files
  if (blob.size === 0) {
    throw new Error('Downloaded report file is empty (0 bytes).')
  }

  // Verify PDF header magic bytes %PDF-
  if (expectedMimeType?.includes('pdf')) {
    const headerBuffer = await blob.slice(0, 5).arrayBuffer()
    const headerBytes = new Uint8Array(headerBuffer)
    const headerStr = String.fromCharCode(...headerBytes)
    if (headerStr !== '%PDF-') {
      throw new Error('Downloaded file does not contain a valid PDF signature (%PDF-).')
    }
  }

  // Extract filename from Content-Disposition header if present
  let filename = defaultFilename
  const disposition = response.headers.get('content-disposition')
  if (disposition && disposition.includes('filename=')) {
    const match = disposition.match(/filename=["']?([^"';]+)["']?/)
    if (match && match[1]) {
      filename = match[1].trim()
    }
  }

  // Create Object URL and trigger download
  const blobUrl = window.URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = blobUrl
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)

  // Delay revoking URL so the browser download manager can asynchronously complete
  setTimeout(() => {
    window.URL.revokeObjectURL(blobUrl)
  }, 60000)
}

// ─── Typed API Interfaces ─────────────────────────────────────────────────────

export interface HealthResponse {
  status: string
  service: string
}

export interface StatsResponse {
  totalScans: number
  vulnerabilitiesFound: number
  criticalIssues: number
  lastScan?: string | null
  lastScanTarget?: string | null
  severityTotals: SeverityCount
}

export interface CreateScanResponse {
  id: string
  reportId: string
  target: string
  scanType: string
  status: string
  startedAt: string
  completedAt: string
  duration: number
  findings: number
  severity: string
  score: number
  grade: string
  message: string
}

// ─── API Client Methods ───────────────────────────────────────────────────────

export const apiClient = {
  /** GET /api/health */
  getHealth: () => request<HealthResponse>('/api/health'),

  /** GET /api/scans/stats */
  getStats: () => request<StatsResponse>('/api/scans/stats'),

  /** GET /api/scans */
  listScans: () => request<Scan[]>('/api/scans'),

  /** GET /api/scans/:id */
  getScan: (id: string) => request<Scan & { findingsList: ReportDetail['findings_list'] }>(`/api/scans/${id}`),

  /** POST /api/scans */
  createScan: (payload: ScanCreatePayload) =>
    request<CreateScanResponse>('/api/scans', { method: 'POST', body: payload }),

  /** GET /api/reports */
  listReports: () => request<Report[]>('/api/reports'),

  /** GET /api/reports/:id */
  getReport: (id: string) => request<ReportDetail>(`/api/reports/${id}`),

  /** GET /api/reports/:id/pdf (Binary PDF Download) */
  downloadReportPdf: (id: string) =>
    downloadFile(`/api/reports/${id}/pdf`, `vulnwatch-report-${id}.pdf`, 'application/pdf'),

  /** GET /api/reports/:id/download?format=json (JSON Export) */
  downloadReportJson: (id: string) =>
    downloadFile(`/api/reports/${id}/download?format=json`, `vulnwatch-report-${id}.json`, 'application/json'),
}
