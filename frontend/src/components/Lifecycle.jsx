import { useState } from 'react'
import { postLifecycle } from '../api.js'
import { fmtTime } from '../format.js'

/** A tracked finding's status workflow (app/services/lifecycle.py, aligned
 *  with NIST SP 800-61r3 / CSF 2.0). Only the next legal step is offered,
 *  and each form asks for exactly what that step requires - but the server
 *  enforces the same rules, so a refusal is shown, never swallowed. */
export default function Lifecycle({ caseId, finding, assignees, classifications, reviewed, onChanged }) {
  const lc = finding.lifecycle
  const [form, setForm] = useState('') // '', 'contain', 'resolve', 'reopen'
  const [assignee, setAssignee] = useState(lc.assignee || '')
  const [text, setText] = useState('')
  const [cls, setCls] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function send(action, extra = {}) {
    setBusy(true)
    setError('')
    try {
      await postLifecycle(caseId, { finding_key: finding.key, action, ...extra })
      setForm('')
      setText('')
      setCls('')
      await onChanged()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const status = lc.status
  const names = Object.fromEntries((assignees || []).map((a) => [a.email, a.name]))

  return (
    <div className={`lc lc-${status.toLowerCase()}`}>
      <div className="lc-head">
        <span className="lc-status" title={lc.csf}>
          {status}
        </span>
        {lc.assignee ? (
          <span className="lc-who">assigned to {names[lc.assignee] || lc.assignee}</span>
        ) : (
          <span className="lc-who muted">unassigned</span>
        )}
        {status === 'Resolved' && (
          <span className="lc-who">
            · {classifications?.[lc.classification] || lc.classification} · {fmtTime(lc.resolved_at)}
          </span>
        )}
        {status === 'Contained' && <span className="lc-who">· contained {fmtTime(lc.contained_at)}</span>}
      </div>

      {status !== 'Resolved' && (
        <div className="lc-actions">
          <select value={assignee} onChange={(e) => setAssignee(e.target.value)} aria-label="Assignee">
            <option value="">- assignee -</option>
            {(assignees || []).map((a) => (
              <option key={a.email} value={a.email}>
                {a.name}
              </option>
            ))}
          </select>
          {assignee && assignee !== lc.assignee && status !== 'Open' && (
            <button className="rv-btn" disabled={busy} onClick={() => send('assign', { assignee })}>
              Reassign
            </button>
          )}
          {status === 'Open' && (
            <button
              className="rv-btn"
              disabled={busy || !assignee}
              title={assignee ? '' : 'Choose an assignee first'}
              onClick={() => send('investigate', { assignee })}
            >
              Start investigating
            </button>
          )}
          {status === 'Investigating' && (
            <button className="rv-btn" disabled={busy} onClick={() => setForm(form === 'contain' ? '' : 'contain')}>
              Mark contained
            </button>
          )}
          {(status === 'Investigating' || status === 'Contained') && (
            <button
              className="rv-btn"
              disabled={busy || !reviewed}
              title={reviewed ? '' : 'Review the finding (accept, modify or reject) first'}
              onClick={() => setForm(form === 'resolve' ? '' : 'resolve')}
            >
              Resolve
            </button>
          )}
        </div>
      )}
      {status === 'Resolved' && (
        <div className="lc-actions">
          <button className="rv-btn" disabled={busy} onClick={() => setForm(form === 'reopen' ? '' : 'reopen')}>
            Reopen
          </button>
        </div>
      )}

      {form === 'contain' && (
        <form
          className="lc-form"
          onSubmit={(e) => {
            e.preventDefault()
            send('contain', { containment_actions: text })
          }}
        >
          <label htmlFor={`contain-${finding.key}`}>Containment actions taken (required)</label>
          <textarea id={`contain-${finding.key}`} value={text} onChange={(e) => setText(e.target.value)} />
          <button className="rv-btn" type="submit" disabled={busy || !text.trim()}>
            Record containment
          </button>
        </form>
      )}

      {form === 'resolve' && (
        <form
          className="lc-form"
          onSubmit={(e) => {
            e.preventDefault()
            send('resolve', { classification: cls, summary: text })
          }}
        >
          <label htmlFor={`cls-${finding.key}`}>Classification (required)</label>
          <select id={`cls-${finding.key}`} value={cls} onChange={(e) => setCls(e.target.value)}>
            <option value="">- choose -</option>
            {Object.entries(classifications || {}).map(([k, v]) => (
              <option key={k} value={k} disabled={k === 'true_positive' && status !== 'Contained'}>
                {v}
                {k === 'true_positive' && status !== 'Contained' ? ' (contain it first)' : ''}
              </option>
            ))}
          </select>
          <label htmlFor={`sum-${finding.key}`}>Summary - what happened and what was done (required)</label>
          <textarea id={`sum-${finding.key}`} value={text} onChange={(e) => setText(e.target.value)} />
          <button className="rv-btn" type="submit" disabled={busy || !cls || !text.trim()}>
            Resolve
          </button>
        </form>
      )}

      {form === 'reopen' && (
        <form
          className="lc-form"
          onSubmit={(e) => {
            e.preventDefault()
            send('reopen', { note: text })
          }}
        >
          <label htmlFor={`reopen-${finding.key}`}>Why reopen it? (required)</label>
          <textarea id={`reopen-${finding.key}`} value={text} onChange={(e) => setText(e.target.value)} />
          <button className="rv-btn" type="submit" disabled={busy || !text.trim()}>
            Reopen
          </button>
        </form>
      )}

      {status === 'Contained' && lc.containment_actions && (
        <div className="lc-note">Containment: {lc.containment_actions}</div>
      )}
      {status === 'Resolved' && lc.summary && <div className="lc-note">Summary: {lc.summary}</div>}
      {error && <div className="lc-error">{error}</div>}
    </div>
  )
}
