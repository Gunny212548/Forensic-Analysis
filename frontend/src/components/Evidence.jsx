import { useCallback, useEffect, useState } from 'react'
import { getCustody, verifyEvidence } from '../api.js'
import { fmtBytes } from '../format.js'
import { Empty } from './common.jsx'

/** Evidence integrity + chain of custody (app/services/custody.py).
 *  The digest is what makes every finding on this case citable: it shows the
 *  file analysed is the file that was handed over. */

/** Custody times are stored in UTC; shown in GMT+7 like every other time in
 *  the app (CLAUDE.md gotcha #21), with the zone written out. Asia/Bangkok
 *  has no DST, so a fixed offset is exact. */
function gmt7(iso) {
  if (!iso) return ''
  const t = new Date(iso)
  if (Number.isNaN(t.getTime())) return iso
  return `${new Date(t.getTime() + 7 * 3600e3).toISOString().slice(0, 19).replace('T', ' ')} +07:00`
}

const ACTION_EN = {
  acquired: 'Acquired (uploaded)',
  acquired_retroactively: 'Digest recorded retroactively',
  derived: 'Derived by merging other cases',
  used_in_merge: 'Used as a source in a merge',
  verified: 'Integrity verified',
  unverified: 'Checked - no acquisition digest to compare',
  integrity_failed: 'INTEGRITY CHECK FAILED',
  processed: 'Processed',
}

function detail(e) {
  if (e.action === 'acquired' || e.action === 'acquired_retroactively') {
    return [e.original_filename, e.bytes != null && fmtBytes(e.bytes), e.client_address && `from ${e.client_address}`]
      .filter(Boolean)
      .join(' · ')
  }
  if (e.action === 'derived') return `${(e.sources || []).length} source cases, ${fmtBytes(e.bytes)}`
  if (e.action === 'used_in_merge') return `merged into ${e.merged_into}`
  if (e.action === 'integrity_failed') return `expected ${e.expected}`
  if (e.action === 'processed') return `${(e.rows ?? 0).toLocaleString()} rows, ${(e.flagged ?? 0).toLocaleString()} flagged`
  return e.purpose || e.note || ''
}

export default function Evidence({ caseId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  // undefined = not checked this visit; true / false / null = the server's
  // answer (null: no acquisition digest exists to compare with).
  const [lastCheck, setLastCheck] = useState(undefined)

  const load = useCallback(async () => {
    try {
      setData(await getCustody(caseId))
    } catch (err) {
      setError(err.message)
    }
  }, [caseId])

  useEffect(() => {
    load()
  }, [load])

  async function verify() {
    setBusy(true)
    setError('')
    try {
      const r = await verifyEvidence(caseId)
      setLastCheck(r.match)
      setData(r)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  if (error && !data) return <Empty>{error}</Empty>
  if (!data) return <Empty>Loading...</Empty>

  const ev = data.evidence
  const entries = data.entries || []
  const failed = entries.some((e) => e.action === 'integrity_failed')

  return (
    <div className="evidence">
      {!ev && (
        <div className="map-note map-warn">
          No acquisition digest was recorded for this file - it was uploaded before digests existed.
          Nothing shows that the file analysed is the file that was handed over.
        </div>
      )}
      {ev && (
        <dl className="ev-facts">
          <dt>SHA-256</dt>
          <dd className="mono ev-hash">{ev.sha256}</dd>
          <dt>Size</dt>
          <dd>{fmtBytes(ev.bytes)} as stored (a compressed upload is kept and hashed compressed)</dd>
          <dt>Recorded</dt>
          <dd>
            {gmt7(ev.recorded_at)} by {ev.recorded_by}
            {ev.retroactive && (
              <div className="map-note map-warn">
                Recorded retroactively: this digest proves the file has not changed since{' '}
                {gmt7(ev.recorded_at)}, not since it was uploaded.
              </div>
            )}
          </dd>
        </dl>
      )}

      <div className="ev-actions">
        <button className="secondary" onClick={verify} disabled={busy}>
          {busy ? 'Hashing the preserved file...' : 'Verify integrity now'}
        </button>
        {lastCheck === true && <span className="ev-ok">Matches the recorded digest.</span>}
        {lastCheck === false && <span className="ev-bad">Does NOT match - the evidence has changed.</span>}
        {lastCheck === null && <span className="muted">Hashed, but there is no acquisition digest to compare with.</span>}
      </div>
      {error && <Empty>{error}</Empty>}
      {failed && (
        <div className="map-note map-warn">
          An integrity check on this case has failed. Findings computed after that point must not be relied on.
        </div>
      )}

      <h3 className="section-label">Chain of custody</h3>
      <div className={data.chain_intact ? 'ev-ok' : 'ev-bad'}>
        {entries.length === 0
          ? 'No custody events recorded yet.'
          : data.chain_intact
            ? entries.length === 1
              ? 'Log intact: its one entry matches its hash.'
              : `Log intact: all ${entries.length} entries link by hash.`
            : `Log altered: ${data.chain_problem}`}
      </div>
      {entries.length > 0 && (
        <table className="ev-log">
          <thead>
            <tr>
              <th>#</th>
              <th>When</th>
              <th>Event</th>
              <th>By</th>
              <th>Details</th>
              <th>SHA-256</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.seq} className={e.action === 'integrity_failed' ? 'ev-row-bad' : ''}>
                <td className="mono">{e.seq}</td>
                <td className="mono">{gmt7(e.ts)}</td>
                <td>{ACTION_EN[e.action] || e.action}</td>
                <td>{e.actor}</td>
                <td>{detail(e)}</td>
                <td className="mono ev-short" title={e.sha256}>
                  {e.sha256 ? `${e.sha256.slice(0, 12)}…` : ''}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="meta-line">
        Method follows{' '}
        {(data.standards || []).map((s, i) => (
          <span key={s.id} title={s.title}>
            {i ? ', ' : ''}
            {s.id}
          </span>
        ))}
        . Each log entry carries the hash of the one before it, so an edit to an earlier entry shows here
        as "Log altered".
      </div>
    </div>
  )
}
