import { SEV_LABEL, severityBucket, statusOf } from '../format.js'

/** Case-list severity at a glance, so a critical case is visible without
 *  opening it. Bucketed server-side from the rule engine's 0-15 lvl
 *  (db.severity_summary). */
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
    <a className={`btn-link ${ready ? '' : 'disabled'}`} href={ready ? `#/result/${caseId}` : '#'}>
      {children}
    </a>
  )
}
