import { useEffect, useState } from 'react'
import { getRules } from '../api.js'
import { LEVEL_EN } from '../format.js'

/** One detection rule's documentation, opened from a finding: the Sigma
 *  metadata and the ADS sections (app/services/rule_meta.py). An analyst
 *  deciding accept/reject needs exactly this - what the rule looks for, what
 *  else produces the same signal, and what it cannot see. */

const STATUS_NOTE = {
  stable: 'Proven in production use.',
  test: 'Validated on real data; may need tuning for a new environment.',
  experimental: 'Not validated on real data yet - weigh its findings accordingly.',
  deprecated: 'Replaced by another rule.',
  unsupported: 'Cannot be used in its current state.',
}

export default function RuleCard({ rid }) {
  const [rule, setRule] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let alive = true
    getRules()
      .then((all) => alive && setRule(all.find((r) => r.rid === rid) || null))
      .catch((err) => alive && setError(err.message))
    return () => {
      alive = false
    }
  }, [rid])

  if (error) return <div className="rule-card muted">{error}</div>
  if (!rule) return <div className="rule-card muted">Loading rule...</div>
  const a = rule.ads

  return (
    <div className="rule-card">
      <div className="rule-head">
        <strong>
          {rule.rid} · {rule.title}
        </strong>
        <span className={`rule-status rule-status-${rule.status}`} title={STATUS_NOTE[rule.status]}>
          {rule.status}
        </span>
        <span className={`sev-tag sev-tag-${rule.level}`}>{LEVEL_EN[rule.level]}</span>
      </div>
      {rule.status === 'experimental' && <div className="rule-warn">{STATUS_NOTE.experimental}</div>}
      <dl className="rule-ads">
        <dt>Goal</dt>
        <dd>{a.goal}</dd>
        <dt>How it works</dt>
        <dd>{a.strategy_abstract}</dd>
        <dt>Context</dt>
        <dd>{a.technical_context}</dd>
        <dt>Blind spots</dt>
        <dd>{a.blind_spots_and_assumptions}</dd>
        <dt>False positives</dt>
        <dd>{a.false_positives.join(' · ')}</dd>
        <dt>Validation</dt>
        <dd>{a.validation}</dd>
        <dt>Response</dt>
        <dd>{a.response}</dd>
        <dt>ATT&amp;CK</dt>
        <dd>
          {rule.references.length
            ? rule.references.map((u) => (
                <a key={u} href={u} target="_blank" rel="noreferrer noopener" className="rule-ref">
                  {u.replace('https://attack.mitre.org/techniques/', '').replace(/\/$/, '').replace('/', '.')}
                </a>
              ))
            : 'none - context only'}
        </dd>
      </dl>
      <div className="meta-line">
        Sigma id <span className="mono">{rule.id}</span> · documented per the Sigma rules specification and
        the ADS framework
      </div>
    </div>
  )
}
