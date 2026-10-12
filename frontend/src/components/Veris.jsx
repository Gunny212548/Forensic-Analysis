import { useEffect, useState } from 'react'
import { getVeris } from '../api.js'

/** The case's incident classification in VERIS's 4 A's (app/services/
 *  veris.py) - computed from the high/critical findings, not written by the
 *  AI, and handed to the AI as a fact to use. */
export default function Veris({ caseId }) {
  const [rec, setRec] = useState(undefined)

  useEffect(() => {
    let alive = true
    getVeris(caseId)
      .then((r) => alive && setRec(r))
      .catch(() => alive && setRec(null))
    return () => {
      alive = false
    }
  }, [caseId])

  if (!rec) return null
  const actor = rec.actor || {}
  const actorText = [
    actor.external && 'External',
    actor.internal && 'Internal',
    actor.unknown && 'Unknown (internal address)',
  ]
    .filter(Boolean)
    .join(' · ')
  const actions = Object.entries(rec.action || {}).map(
    ([cat, v]) => `${cat}: ${v.variety.join(', ')} (via ${v.vector.join(', ')})`,
  )
  const asset = rec.asset?.assets?.[0]
  const conf = rec.attribute?.confidentiality?.data_disclosure

  return (
    <div className="veris">
      <div className="veris-head">
        Incident classification (VERIS 4A) <span className="veris-status">{rec.security_incident}</span>
        <span className="muted"> · confidence {rec.confidence}</span>
      </div>
      <dl className="ev-facts veris-4a">
        <dt>Actor</dt>
        <dd title={[actor.external?.notes, actor.unknown?.notes].filter(Boolean).join('\n')}>{actorText}</dd>
        <dt>Action</dt>
        <dd>
          {actions.map((a) => (
            <div key={a}>{a}</div>
          ))}
        </dd>
        <dt>Asset</dt>
        <dd title={rec.asset?.notes}>
          {asset ? `${asset.amount} affected` : '-'}
          {rec.asset?.notes ? ` - ${rec.asset.notes.replace(/^Affected: /, '')}` : ''}
        </dd>
        <dt>Attribute</dt>
        <dd>{conf ? `Confidentiality: data ${conf.toLowerCase()} disclosed` : 'Not established from the logs'}</dd>
      </dl>
      <div className="meta-line" style={{ marginTop: 4 }}>
        Computed from the high/critical findings, not by the AI ·{' '}
        <a href={`/api/cases/${encodeURIComponent(caseId)}/veris`} download>
          Download VERIS record
        </a>
      </div>
    </div>
  )
}
