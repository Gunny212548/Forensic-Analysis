import { useEffect, useState } from 'react'
import { getRule } from '../api.js'
import { SEV_LABEL, severityBucket, statusOf } from '../format.js'

/** A rule as an analyst reads it. Ours keep their short id (WIN-AUTH-1, R2005) - a code the
 *  analyst learns; SigmaHQ's id is a UUID nobody can read, so it shows the rule's own title,
 *  cut to `max` characters. Either way the hover has the title and the id. */
export function RuleName({ rid, max = 48 }) {
  const [title, setTitle] = useState('')
  useEffect(() => {
    let alive = true
    getRule(rid).then((r) => alive && setTitle(r.title || '')).catch(() => {})
    return () => {
      alive = false
    }
  }, [rid])
  const sigma = String(rid).startsWith('SIGMA-')
  let text = rid
  if (sigma) text = !title ? 'SigmaHQ rule' : title.length > max ? `${title.slice(0, max - 1)}…` : title
  return <span title={title ? `${title}\n${rid}` : rid}>{text}</span>
}

/** Rules as tags (the risk ranking). */
export function RuleTags({ list }) {
  if (!list || !list.length) return null
  return (
    <>
      {list.map((rid) => (
        <span className="mitre-tag" key={rid}>
          <RuleName rid={rid} max={40} />
        </span>
      ))}
    </>
  )
}

/** What each data-quality flag on a suggestion (db._flags) means, in words. */
export const FLAG_TEXT = {
  'no-parsed-timestamp': ['No time', "The source's time could not be read, so when it happened is unknown."],
  'timezone-unconfirmed': ['Time zone assumed', 'The log does not state its time zone; GMT+7 was assumed.'],
  'timezone-declared': ['Time zone declared', 'The log does not state its time zone; the zone the analyst declared was applied.'],
  'year-inferred': ['Year inferred', 'The log lines carry no year (RFC 3164); the year was inferred.'],
  'single-source': ['One kind of rule', 'Only one family of rules saw this - no independent second detection.'],
  'few-events': ['Few events', 'Fewer than 5 events stand behind it.'],
  'experimental-rule': ['New rule', 'The rule is experimental: not yet validated on enough real data.'],
}

/** Case-list severity at a glance, so a critical case is visible without
 *  opening it. Bucketed server-side from the findings' Sigma levels
 *  (severity.summary). */
export function SeverityPill({ severity }) {
  const bucket = severityBucket(severity)
  if (!bucket) return <span className="sev-pill sev-low">—</span>
  const title =
    `critical ${severity.critical || 0} · high ${severity.high || 0} · ` +
    `medium ${severity.medium || 0} · low ${severity.low || 0}`
  return (
    <span className={`sev-pill sev-${bucket}`} title={title}>
      {SEV_LABEL[bucket]}
    </span>
  )
}

export function StatusBadge({ status, error }) {
  const [label, cls] = statusOf(status)
  return (
    <span className={`badge ${cls}`} title={error || ''}>
      {label}
    </span>
  )
}

/** MITRE ids come from the rule engine, already attached to the finding.
 *  The UI never invents or infers one. */
export function MitreTags({ list }) {
  if (!list || !list.length) return null
  return (
    <>
      {list.map((m) => (
        <span className="mitre-tag" key={m}>
          {m}
        </span>
      ))}
    </>
  )
}

export function Empty({ children, style }) {
  return (
    <div className="empty" style={style}>
      {children}
    </div>
  )
}

export function ResultLink({ caseId, ready, children }) {
  return (
    <a className={`btn-link ${ready ? '' : 'disabled'}`} href={ready ? `#/case/${caseId}` : '#'}>
      {children}
    </a>
  )
}
