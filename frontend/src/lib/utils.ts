/**
 * VulnWatch — Utility helpers
 * ============================
 * Pure functions shared across the frontend.
 */

/**
 * Format an ISO-8601 datetime string to a human-readable local date.
 * e.g. "2026-09-26T14:32:00Z" → "26 Sep 2026"
 */
export function formatDate(iso: string): string {
  try {
    return new Intl.DateTimeFormat('en-GB', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
    }).format(new Date(iso))
  } catch {
    return iso
  }
}

/**
 * Format an ISO-8601 datetime string to include the time.
 * e.g. "2026-09-26T14:32:00Z" → "26 Sep 2026, 14:32"
 */
export function formatDateTime(iso: string): string {
  try {
    return new Intl.DateTimeFormat('en-GB', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(new Date(iso))
  } catch {
    return iso
  }
}

/**
 * Format a duration in seconds to a human-readable string.
 * e.g. 135 → "2m 15s" | 42 → "42s"
 */
export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return s === 0 ? `${m}m` : `${m}m ${s}s`
}

/**
 * Truncate a string to maxLen characters, adding an ellipsis if truncated.
 */
export function truncate(str: string, maxLen: number): string {
  return str.length > maxLen ? `${str.slice(0, maxLen)}…` : str
}

/**
 * Clamp a number between min and max.
 */
export function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max)
}
