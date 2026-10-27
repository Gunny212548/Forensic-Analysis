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

function FactIds({ ids, facts }) {
  return (ids || []).map((id) => (
    <span key={id} className="ai-fact" title={facts[id] || 'not among the facts given'}>
      {id.split('.').pop()}
    </span>
  ))
}

function Claims({ items, facts }) {
  if (!(items || []).length) return <span className="muted">nothing in the facts</span>
  return (
    <ul className="ai-reasons">
      {items.map((x, i) => (
        <li key={i}>
          {x.text} <FactIds ids={x.facts} facts={facts} />
        </li>
      ))}
    </ul>
  )
}

function Warnings({ r }) {
  return (
    <>
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
    </>
  )
}

/** Advice written before 2026-10-27, when the AI still gave a verdict - shown as it was
 *  written (specs/ai_triage_verdicts.md X-D4) until the case is reviewed again. */
function OldAdvice({ r }) {
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
          · written before the AI stopped suggesting decisions - Review again above replaces it with an explanation
        </span>
      </div>
      <div><b>Why it fired:</b> {r.why_it_fired}</div>
      <div><b>Likely cause:</b> {r.cause}</div>
      {(r.reasons || []).length > 0 && <Claims items={r.reasons} facts={facts} />}
      {r.matches_false_positive && r.matches_false_positive !== 'none' && (
        <div><b>Matches a documented false positive:</b> {r.matches_false_positive}</div>
      )}
      {r.check_next && <div><b>Check next:</b> {r.check_next}</div>}
      <Warnings r={r} />
    </div>
  )
}

/** The AI's explanation of one suggestion (app/services/triage.py, specs/ai_triage_verdicts.md):
 *  what happened, why the rule fired, the facts on each side - each citing the facts it was
 *  given (hover a fact id to read it) - what the facts do not show and where to look next.
 *  It never says accept or reject: the analyst decides. */
export default function AiReview({ r, state = null, error = null }) {
  if (!r) {
    if (state === 'pending')
      return (
        <div className="ai-review ai-pending">
          <span className="ai-label">AI explanation</span> <span className="muted">pending - every suggestion is explained; this one has not had its turn yet</span>
        </div>
      )
    if (state === 'failed')
      return (
        <div className="ai-review ai-pending">
          <span className="ai-label">AI explanation</span> <span className="muted">not written{error ? `: ${error}` : ''} - use Review again above</span>
        </div>
      )
    return null
  }
  if (!r.what_happened || typeof r.what_happened !== 'object') return <OldAdvice r={r} />
  const facts = r.facts || {}
  return (
    <div className="ai-review">
      <div className="ai-head">
        <span className="ai-label">AI explanation</span>
        <span className="muted">from the facts the system computed · it does not decide, you do</span>
      </div>
      <div><b>What happened:</b> {r.what_happened.text} <FactIds ids={r.what_happened.facts} facts={facts} /></div>
      {r.why_it_fired && (
        <div><b>Why the rule fired:</b> {r.why_it_fired.text} <FactIds ids={r.why_it_fired.facts} facts={facts} /></div>
      )}
      <div className="ai-sides">
        <div><b>Fits an attack:</b> <Claims items={r.points_to_attack} facts={facts} /></div>
        <div><b>Fits an ordinary cause:</b> <Claims items={r.points_to_ordinary_cause} facts={facts} /></div>
      </div>
      {r.resembles_false_positive && r.resembles_false_positive !== 'none' && (
        <div>
          <b>Resembles a documented false positive:</b> {r.resembles_false_positive}
          {r.fp_elsewhere && (
            <span className="ai-warn"> - documented for another rule reviewed with this one, not for this rule</span>
          )}
        </div>
      )}
      {(r.not_shown || []).length > 0 && (
        <div>
          <b>Not shown by the facts:</b>
          <ul className="ai-reasons">{r.not_shown.map((x, i) => <li key={i}>{x}</li>)}</ul>
        </div>
      )}
      {r.check_next && <div><b>Check next:</b> {r.check_next}</div>}
      <Warnings r={r} />
    </div>
  )
}
