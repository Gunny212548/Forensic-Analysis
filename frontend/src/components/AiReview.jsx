const ASSESSMENT_CLASS = {
  'likely attack': 'ai-attack',
  'likely benign': 'ai-benign',
  uncertain: 'ai-uncertain',
}
const DECISION = { accept: 'Accept', reject: 'Reject', undecided: 'No suggestion' }
const REASON = {
  misinterpretation: 'Misinterpretation',
  insufficient_evidence: 'Insufficient evidence',
  better_technique: 'A better-matching technique exists',
  other: 'Other',
}

/** The AI's advice on one suggestion (app/services/triage.py, specs/ai_triage.md):
 *  why the rule fired, the likely cause, its reasons - each citing the facts it
 *  was given (hover a fact id to read it) - and what it would press. Advice
 *  only: the analyst decides. */
export default function AiReview({ r }) {
  if (!r) return null
  const facts = r.facts || {}
  return (
    <div className="ai-review">
      <div className="ai-head">
        <span className="ai-label">AI review</span>
        <span className={`ai-chip ${ASSESSMENT_CLASS[r.assessment] || 'ai-uncertain'}`}>{r.assessment}</span>
        <span className="muted">
          suggests {DECISION[r.suggested_decision] || r.suggested_decision}
          {r.suggested_decision === 'reject' && r.reject_reason && r.reject_reason !== 'none'
            ? ` (${REASON[r.reject_reason] || r.reject_reason})`
            : ''}{' '}
          · advice only, you decide
        </span>
      </div>
      <div><b>Why it fired:</b> {r.why_it_fired}</div>
      <div><b>Likely cause:</b> {r.cause}</div>
      {(r.reasons || []).length > 0 && (
        <ul className="ai-reasons">
          {r.reasons.map((x, i) => (
            <li key={i}>
              {x.text}{' '}
              {(x.facts || []).map((id) => (
                <span key={id} className="ai-fact" title={facts[id] || 'not among the facts given'}>
                  {id.split('.').pop()}
                </span>
              ))}
            </li>
          ))}
        </ul>
      )}
      {r.matches_false_positive && r.matches_false_positive !== 'none' && (
        <div><b>Matches a documented false positive:</b> {r.matches_false_positive}</div>
      )}
      {r.check_next && <div><b>Check next:</b> {r.check_next}</div>}
      {(r.cited_elsewhere || []).length > 0 && (
        <div className="ai-warn">
          Also cites {r.cited_elsewhere.join(', ')}, facts of another suggestion reviewed with this one.
        </div>
      )}
      {(r.ungrounded || []).length > 0 && (
        <div className="ai-warn">
          Names {r.ungrounded.join(', ')}, which none of the facts it was given holds - check before relying on it.
        </div>
      )}
    </div>
  )
}
