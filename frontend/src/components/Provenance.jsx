import { useState } from 'react'
import { putProvenance, reprocessCase } from '../api.js'
import { fmtNum } from '../format.js'

/** Where each evidence item came from, and what its clock said
 *  (app/services/provenance.py). Every field optional (D9). A declared zone
 *  or clock offset applies only when the analyst re-processes - nothing
 *  re-processes on its own. */

const LABELS = {
  source_system: 'Source system',
  export_method: 'How it was exported (method, query or filter)',
  exported_by: 'Exported by',
  exported_at: 'Exported at',
  source_timezone: "Source's time zone (UTC offset, e.g. +00:00)",
  clock_offset_seconds: 'Source clock ahead by (seconds; negative = behind)',
  note: 'Note',
}

function ItemCard({ caseId, item, single, onSaved }) {
  const p = item.provenance || {}
  const a = item.time_applied
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState({})
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  function edit() {
    setDraft(Object.fromEntries(Object.keys(LABELS).map((k) => [k, p[k] ?? ''])))
    setError('')
    setEditing(true)
  }

  async function save(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await putProvenance(caseId, single ? null : item.item, draft)
      setEditing(false)
      onSaved()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const recorded = Object.keys(LABELS).filter((k) => p[k] !== undefined && p[k] !== '')
  return (
    <div className="ing-item">
      <div className="ing-item-head mono">{item.item || 'uploaded file'}</div>
      {a && (
        <div className="cell-sub">
          {fmtNum(a.rows_with_offset)} events state their time zone, {fmtNum(a.rows_without_offset)} do not
          {a.rows_without_offset > 0 && !a.zone && ' (taken as GMT+7)'}
          {a.zone && ` - read as ${a.zone}`}
          {a.clock_offset_seconds ? `, clock corrected by ${-a.clock_offset_seconds} s` : ''}
          {a.rows_shifted ? ` - ${fmtNum(a.rows_shifted)} times moved` : ''}
        </div>
      )}
      {editing ? (
        <form className="lc-form ing-form" onSubmit={save}>
          {Object.entries(LABELS).map(([k, label]) => (
            <div key={k}>
              <label htmlFor={`pv-${item.item}-${k}`}>{label}</label>
              {k === 'export_method' || k === 'note' ? (
                <textarea
                  id={`pv-${item.item}-${k}`}
                  value={draft[k]}
                  onChange={(e) => setDraft({ ...draft, [k]: e.target.value })}
                />
              ) : (
                <input
                  type="text"
                  id={`pv-${item.item}-${k}`}
                  value={draft[k]}
                  onChange={(e) => setDraft({ ...draft, [k]: e.target.value })}
                />
              )}
            </div>
          ))}
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
      ) : (
        <>
          {recorded.length ? (
            <table className="profile-facts">
              <tbody>
                {recorded.map((k) => (
                  <tr key={k}>
                    <td>{LABELS[k].split(' (')[0]}</td>
                    <td>{String(p[k])}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="muted">No provenance recorded.</div>
          )}
          <button className="secondary" type="button" onClick={edit} style={{ marginTop: 6 }}>
            {recorded.length ? 'Edit provenance' : 'Record provenance'}
          </button>
        </>
      )}
    </div>
  )
}

export default function Provenance({ caseId, ingest, onSaved, onReprocessed }) {
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const items = ingest.items || []
  const processing = ['queued', 'processing'].includes(ingest.status)

  async function reprocess() {
    setBusy(true)
    setError('')
    try {
      await reprocessCase(caseId, ingest.reprocess_needed ? 'apply declared time settings' : 'analyst request')
      setConfirm(false)
      onReprocessed()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="ing-items">
        {items.map((it) => (
          <ItemCard key={it.item} caseId={caseId} item={it} single={items.length === 1} onSaved={onSaved} />
        ))}
      </div>
      <div className="lc-actions" style={{ marginTop: 10 }}>
        {!confirm ? (
          <button
            className={ingest.reprocess_needed ? 'rv-btn' : 'secondary'}
            type="button"
            disabled={processing}
            onClick={() => setConfirm(true)}
          >
            {processing ? 'Processing...' : ingest.reprocess_needed ? 'Re-process to apply the time settings' : 'Re-process'}
          </button>
        ) : (
          <>
            <span className="cell-sub">
              Runs every rule again over the preserved original. Review decisions are kept; counts may change.
            </span>
            <button className="rv-btn" type="button" onClick={reprocess} disabled={busy}>
              {busy ? 'Starting...' : 'Re-process now'}
            </button>
            <button className="secondary" type="button" onClick={() => setConfirm(false)} disabled={busy}>
              Cancel
            </button>
          </>
        )}
      </div>
      {error && <div className="lc-error">{error}</div>}
    </>
  )
}

/** The reproducibility record of the last run (app/services/repro.py). */
export function Method({ method }) {
  if (!method) {
    return <div className="muted">No record yet - this case was last processed before records were kept; re-process it to get one.</div>
  }
  const short = (h) => (h ? `${h.slice(0, 16)}…` : '-')
  return (
    <table className="profile-facts">
      <tbody>
        <tr>
          <td>Application code (SHA-256)</td>
          <td className="mono" title={method.app_code_sha256}>{short(method.app_code_sha256)}</td>
        </tr>
        <tr>
          <td>Rule set (SHA-256)</td>
          <td className="mono" title={method.rules_sha256}>
            {short(method.rules_sha256)} · {method.rules} rules
          </td>
        </tr>
        <tr>
          <td>Read through</td>
          <td>{(method.profiles || []).join(', ')}</td>
        </tr>
        <tr>
          <td>Threat-intel feeds</td>
          <td className="mono">
            {(method.intel_feeds || []).length
              ? method.intel_feeds.map((f) => `${f.file} ${f.sha256.slice(0, 12)}…`).join(' · ')
              : 'none'}
          </td>
        </tr>
        <tr>
          <td>DuckDB</td>
          <td className="mono">{method.duckdb}</td>
        </tr>
      </tbody>
    </table>
  )
}
