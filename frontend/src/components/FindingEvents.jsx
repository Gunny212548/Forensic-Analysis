import { useCallback } from 'react'
import { getFindingEvents } from '../api.js'
import { fmtNum } from '../format.js'
import { Empty } from './common.jsx'
import VirtualBody from './VirtualBody.jsx'
import { useVirtualRows } from './useVirtualRows.js'

/** The events behind one finding, each with the file it came from (FR-4.1):
 *  how a finding is traced back to its source. One scrolling box whose scrollbar
 *  stands for every event of the finding from the start - a finding can stand for
 *  tens of thousands of rows, so only those in view are drawn and their server
 *  pages fetched as they come into view (useVirtualRows); one event a line, every
 *  record whole (the user, 2026-11-02: scroll to any event, no load more). */
export default function FindingEvents({ caseId, findingKey }) {
  const fetchPage = useCallback(
    (offset, limit) => getFindingEvents(caseId, findingKey, { limit, offset }),
    [caseId, findingKey],
  )
  const v = useVirtualRows(fetchPage, (r) => r.rows, `${caseId}|${findingKey}`, { rowHeight: 28 })
  const sha = v.meta?.evidence_sha256 || ''

  if (v.error && !v.meta) return <Empty>{v.error}</Empty>
  if (!v.meta) return <div className="fe muted">Loading events...</div>

  return (
    <div className="fe">
      {/* One event a line; the box scrolls both ways and its scrollbar is the whole list. */}
      <div className="events-scroll fe-scroll" ref={v.box} onScroll={v.onScroll}>
        <table className="ov-table fe-table events-table vlist">
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
          <VirtualBody
            v={v}
            cols={7}
            row={(e, i, ref) => (
              <tr key={i} ref={ref} data-i={i}>
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
            )}
          />
        </table>
      </div>
      <div className="fe-foot">
        {fmtNum(v.total)} events
        {v.error ? ` - could not load some of them: ${v.error}` : ''}
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
