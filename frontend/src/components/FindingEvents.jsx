import { useCallback, useEffect, useState } from 'react'
import { getFindingEvents } from '../api.js'
import { fmtNum, shortTs } from '../format.js'
import { Empty } from './common.jsx'

const PAGE = 25

/** The events behind one finding, each with the file it came from (FR-4.1):
 *  how a finding is traced back to its source. Loaded when it is opened and
 *  paged from the server - a finding can stand for tens of thousands of rows. */
export default function FindingEvents({ caseId, findingKey }) {
  const [rows, setRows] = useState([])
  const [total, setTotal] = useState(null)
  const [sha, setSha] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(
    async (offset) => {
      setBusy(true)
      try {
        const r = await getFindingEvents(caseId, findingKey, { limit: PAGE, offset })
        setRows((prev) => (offset ? [...prev, ...r.rows] : r.rows))
        setTotal(r.total)
        setSha(r.evidence_sha256 || '')
        setError('')
      } catch (err) {
        setError(err.message)
      } finally {
        setBusy(false)
      }
    },
    [caseId, findingKey],
  )

  useEffect(() => {
    load(0)
  }, [load])

  if (error) return <Empty>{error}</Empty>
  if (total === null) return <div className="fe muted">Loading events...</div>

  return (
    <div className="fe">
      <div className="table-scroll">
        <table className="ov-table fe-table">
          <thead>
            <tr>
              <th>Row</th>
              <th>Time</th>
              <th>Source → target</th>
              <th>Account</th>
              <th>File</th>
              <th>Event</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.row_id}>
                <td className="mono muted">{e.row_id}</td>
                <td className="mono">{shortTs(e.ts) || e.ts_raw || ''}</td>
                <td className="mono">
                  {e.srcip || '—'}
                  {e.dstip ? ` → ${e.dstip}` : ''}
                </td>
                <td className="mono">{e.username || ''}</td>
                <td className="mono">{e.source_file || ''}</td>
                <td className="mono fe-raw" title={e.raw}>
                  {(e.raw || '').slice(0, 160)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="fe-foot">
        Showing {fmtNum(rows.length)} of {fmtNum(total)} events
        {sha && (
          <>
            {' '}
            · evidence SHA-256 <span className="mono" title={sha}>{sha.slice(0, 16)}…</span>
          </>
        )}
        {rows.length < total && (
          <button type="button" className="rv-btn" disabled={busy} onClick={() => load(rows.length)}>
            {busy ? 'Loading...' : 'Load more'}
          </button>
        )}
      </div>
    </div>
  )
}
