import { useState } from 'react'
import { reprocessCase } from '../api.js'
import { useAccess } from '../permissions.js'

/** Re-process the case from its preserved original, and the reproducibility
 *  record of the last run. The Ingest step's Provenance / Source time section
 *  that held this button left the screen on 2026-10-27 (the user: not needed -
 *  Windows events state their zone; a declared zone stays applicable through
 *  the API, app/services/provenance.py). */

export default function Reprocess({ caseId, ingest, onReprocessed }) {
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const { can, why } = useAccess()
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
      <div className="lc-actions" style={{ marginTop: 10 }}>
        {!confirm ? (
          <button
            className={ingest.reprocess_needed ? 'rv-btn' : 'secondary'}
            type="button"
            disabled={processing || !can('case:reprocess')}
            title={why('case:reprocess')}
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
