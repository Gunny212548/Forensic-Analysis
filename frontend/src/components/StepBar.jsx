/** The six steps of a case (case_flow.py), in order, each with its state.
 *
 *  It only shows where the case stands; it never moves the analyst. The step
 *  the server recommends is marked, and the one Next step button is the only
 *  way forward besides clicking a step - every step stays open, because the
 *  order is the recommended one, not a lock on the evidence. */

const STATE_LABEL = {
  done: 'Done',
  active: 'In progress',
  blocked: 'Blocked',
  not_started: 'Not started',
  optional: 'Optional',
}

export function stepHref(caseId, id) {
  return `#/case/${caseId}/${id}`
}

export default function StepBar({ caseId, flow, current }) {
  const steps = flow?.steps || []
  const i = steps.findIndex((s) => s.id === current)
  const next = i >= 0 && i < steps.length - 1 ? steps[i + 1] : null
  return (
    <nav className="stepbar" aria-label="Case steps">
      <ol>
        {steps.map((s, n) => (
          <li key={s.id} className={`step step-${s.state}${s.id === current ? ' current' : ''}`}>
            <a href={stepHref(caseId, s.id)} aria-current={s.id === current ? 'step' : undefined}
               title={s.reason}>
              <span className="step-n">{s.state === 'done' ? '✓' : n + 1}</span>
              <span className="step-text">
                <span className="step-title">
                  {s.title}
                  {flow.recommended === s.id && s.id !== current && <span className="step-rec"> · next</span>}
                </span>
                <span className="step-state">
                  {STATE_LABEL[s.state] || s.state}
                  {s.remaining ? ` · ${s.remaining} left` : ''}
                </span>
              </span>
            </a>
          </li>
        ))}
      </ol>
      {next && (
        <a className="btn-secondary step-next" href={stepHref(caseId, next.id)}>
          Next step: {next.title} &rarr;
        </a>
      )}
    </nav>
  )
}
