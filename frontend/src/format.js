// Formatting helpers, ported from the pre-React page.
//
// Note what is NOT here: escapeHtml(). The old page built every row by
// concatenating innerHTML, so each interpolation of a filename, a company
// name or a rule description had to be escaped by hand - the discipline was
// actually held throughout, but it was one forgotten call away from an
// injection. JSX escapes text nodes for us, so the whole class of mistake is
// gone rather than guarded.

export const STATUS_MAP = {
  queued: ['รอประมวลผล', 'count-0'],
  processing: ['กำลังประมวลผล...', 'count-0'],
  ready: ['พร้อม', 'count-n'],
  failed: ['ล้มเหลว', 'count-fail'],
}

export const SEV_LABEL = {
  critical: 'วิกฤต',
  high: 'สูง',
  medium: 'ปานกลาง',
  low: 'ต่ำ',
  none: 'ไม่พบ',
}

export const SEV_CLASS = {
  critical: 'sev-critical',
  high: 'sev-high',
  medium: 'sev-medium',
  low: 'sev-low',
}

export const REVIEW_CLASS = {
  Unreviewed: 'rv-unreviewed',
  Accepted: 'rv-accepted',
  Modified: 'rv-modified',
  Rejected: 'rv-rejected',
}

export function statusOf(status) {
  return STATUS_MAP[status] || [status, 'count-0']
}

export function fmtBytes(n) {
  if (n == null) return ''
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 ** 3) return `${(n / 1024 / 1024).toFixed(1)} MB`
  return `${(n / 1024 ** 3).toFixed(1)} GB`
}

export function fmtTime(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return String(iso)
  return d.toLocaleString('th-TH', { dateStyle: 'medium', timeStyle: 'medium' })
}

/** Trim an event time to minutes for the narrow spots (chain nodes, review
 *  footers). Event times arrive already normalised to GMT+7 and carrying
 *  their offset (CLAUDE.md gotcha #21), so this only shortens - it never
 *  reinterprets a zone. */
export function shortTs(ts) {
  if (!ts) return ''
  return String(ts).replace('T', ' ').slice(0, 16)
}

/** "14 min ago" - the Figma's relative times, in English like the shell. */
export function ago(iso) {
  if (!iso) return ''
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} hr ago`
  return `${Math.floor(s / 86400)} days ago`
}

export function fmtNum(n) {
  return (n || 0).toLocaleString()
}

export function severityBucket(sev) {
  if (!sev) return null
  if (sev.critical > 0) return 'critical'
  if (sev.high > 0) return 'high'
  if (sev.medium > 0) return 'medium'
  if (sev.low > 0) return 'low'
  return 'none'
}
