/**
 * VulnWatch — Demo / Placeholder Data
 * =====================================
 * All data in this file is FICTIONAL and for UI development only.
 * It is clearly separated from real API responses.
 *
 * ⚠️  IMPORTANT: This data does NOT represent real security findings.
 *     It will be replaced by live API data in Phase 3.
 */

import type { Scan, Report, ReportDetail, DashboardStats, SeverityCount } from '../types'

// ─── Dashboard stats ──────────────────────────────────────────────────────────

export const DEMO_STATS: DashboardStats = {
  totalScans: 14,
  vulnerabilitiesFound: 37,
  criticalIssues: 3,
  lastScan: '2026-09-26T14:32:00Z',
}

// ─── Scans ────────────────────────────────────────────────────────────────────

export const DEMO_SCANS: Scan[] = [
  {
    id: 'SCN-001',
    target: 'http://localhost:5000',
    scanType: 'full',
    status: 'completed',
    startedAt: '2026-09-26T14:30:00Z',
    completedAt: '2026-09-26T14:32:15Z',
    duration: 135,
    findings: 8,
    severity: 'critical',
  },
  {
    id: 'SCN-002',
    target: 'http://localhost:3001',
    scanType: 'headers',
    status: 'completed',
    startedAt: '2026-09-25T10:15:00Z',
    completedAt: '2026-09-25T10:15:42Z',
    duration: 42,
    findings: 5,
    severity: 'high',
  },
  {
    id: 'SCN-003',
    target: 'http://localhost:8080',
    scanType: 'basic',
    status: 'completed',
    startedAt: '2026-09-24T09:00:00Z',
    completedAt: '2026-09-24T09:00:28Z',
    duration: 28,
    findings: 2,
    severity: 'medium',
  },
  {
    id: 'SCN-004',
    target: 'http://localhost:4200',
    scanType: 'cookies',
    status: 'failed',
    startedAt: '2026-09-23T16:45:00Z',
    completedAt: '2026-09-23T16:45:03Z',
    duration: 3,
    findings: 0,
    severity: 'info',
  },
  {
    id: 'SCN-005',
    target: 'http://localhost:5000',
    scanType: 'headers',
    status: 'completed',
    startedAt: '2026-09-22T11:20:00Z',
    completedAt: '2026-09-22T11:20:55Z',
    duration: 55,
    findings: 11,
    severity: 'high',
  },
  {
    id: 'SCN-006',
    target: 'http://localhost:3000',
    scanType: 'basic',
    status: 'completed',
    startedAt: '2026-09-21T08:30:00Z',
    completedAt: '2026-09-21T08:30:19Z',
    duration: 19,
    findings: 3,
    severity: 'low',
  },
  {
    id: 'SCN-007',
    target: 'http://localhost:9000',
    scanType: 'full',
    status: 'completed',
    startedAt: '2026-09-20T13:00:00Z',
    completedAt: '2026-09-20T13:02:05Z',
    duration: 125,
    findings: 7,
    severity: 'critical',
  },
]

// ─── Dashboard recent scans (last 5) ─────────────────────────────────────────

export const DEMO_RECENT_SCANS = DEMO_SCANS.slice(0, 5)

// ─── Severity totals across all scans ────────────────────────────────────────

export const DEMO_SEVERITY_TOTALS: SeverityCount = {
  critical: 3,
  high: 16,
  medium: 9,
  low: 7,
  info: 2,
}

// ─── Reports ──────────────────────────────────────────────────────────────────

export const DEMO_REPORTS: Report[] = [
  {
    id: 'RPT-001',
    scanId: 'SCN-001',
    target: 'http://localhost:5000',
    scannedAt: '2026-09-26T14:32:15Z',
    securityScore: 42,
    findings: 8,
    status: 'ready',
    severityBreakdown: { critical: 2, high: 3, medium: 2, low: 1, info: 0 },
  },
  {
    id: 'RPT-002',
    scanId: 'SCN-002',
    target: 'http://localhost:3001',
    scannedAt: '2026-09-25T10:15:42Z',
    securityScore: 68,
    findings: 5,
    status: 'ready',
    severityBreakdown: { critical: 0, high: 2, medium: 2, low: 1, info: 0 },
  },
  {
    id: 'RPT-003',
    scanId: 'SCN-003',
    target: 'http://localhost:8080',
    scannedAt: '2026-09-24T09:00:28Z',
    securityScore: 85,
    findings: 2,
    status: 'ready',
    severityBreakdown: { critical: 0, high: 0, medium: 1, low: 1, info: 0 },
  },
  {
    id: 'RPT-004',
    scanId: 'SCN-007',
    target: 'http://localhost:9000',
    scannedAt: '2026-09-20T13:02:05Z',
    securityScore: 51,
    findings: 7,
    status: 'ready',
    severityBreakdown: { critical: 1, high: 3, medium: 2, low: 1, info: 0 },
  },
]

// ─── Report detail (for SCN-001) ──────────────────────────────────────────────

export const DEMO_REPORT_DETAIL: ReportDetail = {
  ...DEMO_REPORTS[0],
  summary:
    'This scan identified 8 security findings across the target application. ' +
    '2 critical issues require immediate attention. ' +
    'All findings are based on passive checks of HTTP headers and cookie configuration.',
  findings_list: [
    {
      id: 'F-001',
      title: 'Missing Content-Security-Policy Header',
      severity: 'critical',
      description:
        'The Content-Security-Policy (CSP) header was not present in the HTTP response. ' +
        'CSP helps mitigate cross-site scripting (XSS) and data injection attacks.',
      recommendation:
        "Add a strict Content-Security-Policy header. Example: Content-Security-Policy: default-src 'self'",
      location: 'HTTP Response Headers',
    },
    {
      id: 'F-002',
      title: 'Missing X-Frame-Options Header',
      severity: 'critical',
      description:
        'The X-Frame-Options header is absent, which may allow the application to be ' +
        'embedded in an iframe on a malicious website (clickjacking attack).',
      recommendation:
        'Set X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN in your server configuration.',
      location: 'HTTP Response Headers',
    },
    {
      id: 'F-003',
      title: 'Missing Strict-Transport-Security Header',
      severity: 'high',
      description:
        'HTTP Strict Transport Security (HSTS) is not configured. This allows potential ' +
        'downgrade attacks if the application is served over HTTPS.',
      recommendation:
        'Add Strict-Transport-Security: max-age=31536000; includeSubDomains to your HTTPS server.',
      location: 'HTTP Response Headers',
    },
    {
      id: 'F-004',
      title: 'Cookie Missing Secure Flag',
      severity: 'high',
      description:
        'One or more cookies are set without the Secure attribute, meaning they could be ' +
        'transmitted over unencrypted HTTP connections.',
      recommendation:
        'Set the Secure flag on all cookies. In most frameworks this is a single configuration option.',
      location: 'Set-Cookie Header',
    },
    {
      id: 'F-005',
      title: 'Cookie Missing HttpOnly Flag',
      severity: 'high',
      description:
        'Cookies without the HttpOnly flag can be accessed by JavaScript, increasing the risk ' +
        'of session hijacking via XSS attacks.',
      recommendation:
        'Add the HttpOnly attribute to session and authentication cookies.',
      location: 'Set-Cookie Header',
    },
    {
      id: 'F-006',
      title: 'Server Header Exposes Version Information',
      severity: 'medium',
      description:
        "The Server HTTP response header reveals the software name and version (e.g., 'nginx/1.18.0'). " +
        'This aids attackers in targeting known vulnerabilities.',
      recommendation:
        "Configure your web server to suppress or genericise the Server header value.",
      location: 'HTTP Response Headers',
    },
    {
      id: 'F-007',
      title: 'X-Content-Type-Options Not Set',
      severity: 'low',
      description:
        'The X-Content-Type-Options: nosniff header is missing. This can allow browsers to ' +
        'MIME-sniff content away from the declared Content-Type.',
      recommendation:
        'Add X-Content-Type-Options: nosniff to all HTTP responses.',
      location: 'HTTP Response Headers',
    },
    {
      id: 'F-008',
      title: 'Referrer-Policy Not Configured',
      severity: 'low',
      description:
        'No Referrer-Policy header was detected. The default browser behaviour may leak ' +
        'URL information to external sites via the Referer header.',
      recommendation:
        "Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
      location: 'HTTP Response Headers',
    },
  ],
}
