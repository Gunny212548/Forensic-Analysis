import { useState } from 'react'
import { putQuestion } from '../api.js'
import { fmtTime } from '../format.js'

/** The question the investigation answers, its time window and known leads
 *  (app/services/investigation.py). Kept on the project when the case is in
 *  one - every case of it shows the same question - else on the case. Every
 *  change is a hash-chained line with who and when; nothing here blocks a
 *  step (D8: the report needs it, story 8). */

const LEADS = [
  ['addresses', 'Addresses'],
  ['accounts', 'Accounts'],
  ['hosts', 'Hosts'],
]

function draftOf(q) {
  return {
    question: q.question || '',
    window_from: q.window_from || '',
    window_to: q.window_to || '',
    ...Object.fromEntries(LEADS.map(([k]) => [k, (q[k] || []).join('\n')])),
  }
}

export default function Question({ caseId, investigation, onSaved }) {
  const q = investigation.question || {}
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(() => draftOf(q))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const where =
    investigation.scope === 'project'
      ? `the investigation (project "${investigation.project_name}")`
      : 'this case (it is in no project)'

  function edit() {
    setDraft(draftOf(q))
    setError('')
    setEditing(true)
  }

  async function save(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await putQuestion(caseId, draft)
      setEditing(false)
      onSaved()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const field = (k) => ({ id: `q-${k}`, value: draft[k], onChange: (e) => setDraft({ ...draft, [k]: e.target.value }) })

  if (editing) {
    return (
      <form className="lc-form ing-form" onSubmit={save}>
        <label htmlFor="q-question">What must this investigation answer? - for {where}</label>
        <textarea {...field('question')} placeholder="e.g. Did anyone sign in to the ESXi host from outside, and what did they do?" />
        <div className="ing-row">
          <div>
            <label htmlFor="q-window_from">Window from (ISO 8601, optional)</label>
            <input type="text" {...field('window_from')} placeholder="2026-02-14T00:00" />
          </div>
          <div>
            <label htmlFor="q-window_to">Window to</label>
            <input type="text" {...field('window_to')} placeholder="2026-02-16T00:00" />
          </div>
        </div>
        <div className="ing-row">
          {LEADS.map(([k, title]) => (
            <div key={k}>
              <label htmlFor={`q-${k}`}>Known {title.toLowerCase()} - one per line</label>
              <textarea {...field(k)} />
            </div>
          ))}
        </div>
        <div className="lc-actions">
          <button className="rv-btn" type="submit" disabled={busy}>
            {busy ? 'Saving...' : 'Save'}
          </button>
          <button className="secondary" type="button" onClick={() => setEditing(false)} disabled={busy}>
            Cancel
          </button>
        </div>
        {error && <div className="lc-error">{error}</div>}
      </form>
    )
  }

  const leads = LEADS.filter(([k]) => (q[k] || []).length)
  return (
    <div className="ing-block">
      {q.question ? (
        <div className="ing-question">{q.question}</div>
      ) : (
        <div className="muted">No question recorded for {where}.</div>
      )}
      {(q.window_from || q.window_to) && (
        <div className="cell-sub">
          Window: {q.window_from || '…'} → {q.window_to || '…'}
        </div>
      )}
      {leads.map(([k, title]) => (
        <div key={k} className="cell-sub">
          {title}: <span className="mono">{q[k].join(', ')}</span>
        </div>
      ))}
      <div className="lc-actions" style={{ marginTop: 8 }}>
        <button className="secondary" type="button" onClick={edit}>
          {q.question ? 'Edit' : 'Record the question'}
        </button>
        {investigation.updated_by && (
          <span className="cell-sub">
            last changed by {investigation.updated_by}, {fmtTime(investigation.updated_at)}
          </span>
        )}
      </div>
    </div>
  )
}
