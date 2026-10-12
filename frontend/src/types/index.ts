/**
 * VulnWatch — Shared Types
 * ========================
 * Central type definitions used across the frontend.
 * Demo/placeholder data is typed here alongside the real interfaces so that
 * the shapes match when the real API is wired in Phase 3.
 */

// ─── Severity ─────────────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface SeverityCount {
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

// ─── Scans ────────────────────────────────────────────────────────────────────

export type ScanStatus = 'completed' | 'running' | 'failed' | 'queued' | 'cancelled'

export type ScanType = 'basic' | 'headers' | 'cookies' | 'full'

export interface Scan {
  id: string
  target: string
  scanType: ScanType
  status: ScanStatus
  startedAt: string       // ISO-8601
  completedAt?: string    // ISO-8601
  duration?: number       // seconds
  findings: number
  severity: Severity      // worst finding severity
}

export interface ScanCreatePayload {
  target_url: string
  scan_type: ScanType
}

// ─── Reports ──────────────────────────────────────────────────────────────────

export type ReportStatus = 'ready' | 'generating' | 'unavailable'

export interface Report {
  id: string
  scanId: string
  target: string
  scannedAt: string
  securityScore: number   // 0–100
  findings: number
  status: ReportStatus
  severityBreakdown: SeverityCount
}

export interface ReportFinding {
  id: string
  title: string
  severity: Severity
  description: string
  recommendation: string
  location?: string
  evidence?: string
  category?: string
  type?: 'missing_control' | 'vulnerability'
}

export interface ReportDetail extends Report {
  summary: string
  findings_list: ReportFinding[]
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

export interface DashboardStats {
  totalScans: number
  vulnerabilitiesFound: number
  criticalIssues: number
  lastScan?: string
}
