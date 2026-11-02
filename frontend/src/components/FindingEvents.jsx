import { useCallback, useEffect, useRef, useState } from 'react'
import { getFindingEvents } from '../api.js'
import { fmtNum } from '../format.js'
import { Empty } from './common.jsx'
import { useLoadOnScroll } from './useLoadOnScroll.js'

const PAGE = 200

/** The events behind one finding, each with the file it came from (FR-4.1):
 *  how a finding is traced back to its source. Loaded when it is opened, from
 *  the server a page at a time - a finding can stand for tens of thousands of
 *  rows - and, like the Timeline's table, the next page comes as the box is
 *  scrolled: one event a line, every record whole, no Load more button (the
 *  user, 2026-11-02: the source events must show every event). */
export default function FindingEvents({ caseId, findingKey }) {
  const [rows, setRows] = useState([])
  const [total, setTotal] = useState(null)
  const [sha, setSha] = useState('')
  const [error, setError] = useState('')
  const [more, setMore] = useState(false)
  const busy = useRef(false)
  const box = useRef(null)
  const end = useRef(null)

  const load = useCallback(
    async (offset) => {
      busy.current = true
      setMore(true)
      try {
        const r = await getFindingEvents(caseId, findingKey, { limit: PAGE, offset })
        setRows((prev) => (offset ? [...prev, ...r.rows] : r.rows))
        setTotal(r.total)
        setSha(r.evidence_sha256 || '')
        setError('')
      } catch (err) {
        setError(err.message)
      } finally {
        busy.current = false
        setMore(false)
      }
    },
    [caseId, findingKey],
  )

  useEffect(() => {
    load(0)
  }, [load])

  const loadMore = useCallback(() => {
    if (busy.current || error || total === null || rows.length >= total) return
    load(rows.length)
  }, [load, error, total, rows.length])
  useLoadOnScroll(box, end, loadMore)

  if (error && !rows.length) return <Empty>{error}</Empty>
  if (total === null) return <div className="fe muted">Loading events...</div>
  const all = rows.length >= total

  return (
    <div className="fe">
      {/* One event a line, the box scrolls both ways (styles.css .events-scroll). */}
      <div className="events-scroll fe-scroll" ref={box}>
        <table className="ov-table fe-table events-table">
          <thead>
            <tr>
              <th>Row</th>
              <th>Time</th>
              <th title="The computer or device that wrote this record - a Windows event's Computer, a syslog line's host, a FortiGate's devname. Not the target.">
                Host
              </th>
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
                {/* The whole time, seconds and zone - two events a second apart are two steps. */}
                <td className="mono">{e.ts || e.ts_raw || ''}</td>
                <td className="mono">{e.hostname || ''}</td>
                <td className="mono">
                  {e.srcip || '—'}
                  {e.dstip ? ` → ${e.dstip}` : ''}
                </td>
                <td className="mono">{e.username || ''}</td>
                <td className="mono">{e.source_file || ''}</td>
                {/* The whole record on one line - the box scrolls sideways to it. */}
                <td className="mono raw-cell">{e.raw || ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="events-end" ref={end}>
          {more ? 'Loading more...' : error ? `Could not load more: ${error}` : all ? 'End of the list' : ''}
        </div>
      </div>
      <div className="fe-foot">
        Showing {fmtNum(rows.length)} of {fmtNum(total)} events
        {all ? '' : ' - scroll the list for more'}
        {sha && (
          <>
            {' '}
            · evidence SHA-256 <span className="mono" title={sha}>{sha.slice(0, 16)}…</span>
          </>
        )}
      </div>
    </div>
  )
}
