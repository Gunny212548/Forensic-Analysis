import { useCallback, useEffect, useState } from 'react'
import { getEvents } from '../api.js'
import { LEVEL_EN, SEV_CLASS, fmtNum } from '../format.js'
import { Empty, MitreTags } from './common.jsx'

const PAGE_SIZE = 100

/** Paginated, server-side. A case can hold 65k+ rows and 25k findings, so
 *  the client never pulls the whole table - the offset lives here and every
 *  page is its own query. FR-11.2: every event of the case by default, the
 *  rule matches one click away. `order` "time" is the Timeline step: every
 *  event by event time, then row (file order is "row"). */
export default function EventsTable({ caseId, order = 'row' }) {
  const [flagged, setFlagged] = useState(false)
  const [offset, setOffset] = useState(0)
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setError('')
    try {
      setData(await getEvents(caseId, { limit: PAGE_SIZE, offset, flagged, order }))
    } catch (err) {
      setError(err.message)
    }
  }, [caseId, offset, flagged, order])

  useEffect(() => {
    load()
  }, [load])

  function showFlagged(on) {
    setFlagged(on)
    setOffset(0)
    setData(null)
  }

  const toggle = (
    <div className="ov-filters">
      <button type="button" className={`chip-btn${flagged ? '' : ' active'}`} onClick={() => showFlagged(false)}>
        All events
      </button>
      <button type="button" className={`chip-btn${flagged ? ' active' : ''}`} onClick={() => showFlagged(true)}>
        Flagged only
      </button>
    </div>
  )

  let body
  if (error) body = <Empty>Could not load: {error}</Empty>
  else if (!data) body = <Empty>Loading...</Empty>
  else if (!data.events.length) {
    body = (
      <Empty>
        {offset > 0
          ? 'No more events'
          : flagged
            ? 'The rule engine flagged nothing in this file'
            : 'No events in this file'}
      </Empty>
    )
  } else {
    const from = data.offset + 1
    const to = data.offset + data.count
    const hasPrev = data.offset > 0
    const hasNext = to < data.total
    body = (
      <>
        <Empty style={{ paddingBottom: 8 }}>
          {flagged
            ? `Showing ${fmtNum(from)}-${fmtNum(to)} of ${fmtNum(data.total)} findings (raw rows in the file: ${fmtNum(data.total_rows)})`
            : `Showing ${fmtNum(from)}-${fmtNum(to)} of ${fmtNum(data.total)} events (${fmtNum(data.flagged_count)} flagged)`}
        </Empty>
        <div className="table-scroll">{flagged ? <FlaggedRows events={data.events} /> : <AllRows events={data.events} />}</div>
        <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
          <button
            className="secondary"
            disabled={!hasPrev}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          >
            &larr; Previous
          </button>
          <button
            className="secondary"
            disabled={!hasNext}
            onClick={() => setOffset(offset + PAGE_SIZE)}
          >
            Next &rarr;
          </button>
        </div>
      </>
    )
  }

  return (
    <>
      {toggle}
      {body}
    </>
  )
}

function AllRows({ events }) {
  return (
    <table>
      <thead>
        <tr>
          <th>time</th>
          <th>source</th>
          <th>destination</th>
          <th>account</th>
          <th>event</th>
          <th>verdict</th>
          <th>application</th>
          <th>context</th>
          <th>raw message</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e) => (
          <tr key={e.row_id}>
            {/* ts is the parsed GMT+7 event time; ts_raw is the source text,
                shown only when nothing parsed (CLAUDE.md gotcha #21). */}
            <td>{e.ts || e.ts_raw || ''}</td>
            <td>{e.srcip || ''}</td>
            <td>{e.dstip || ''}</td>
            <td>{e.username || ''}</td>
            {/* Layer A: the event type, named by the server (db.EVENT_TYPES)
                so the table and the MCP tools use the same words. */}
            <td>{e.event || ''}</td>
            <td>{e.verdict || ''}</td>
            <td>
              {e.app || ''}
              {e.risk != null ? ` · risk ${e.risk}/5` : ''}
            </td>
            {/* Layer C: facts about the event, never a verdict (db.list_raw). */}
            <td>
              {(e.context || []).map((c) => (
                <span key={c} className="context-chip">
                  {c}
                </span>
              ))}
            </td>
            <td className="raw-cell" title={e.raw || ''}>
              {e.raw || ''}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function FlaggedRows({ events }) {
  return (
    <table>
      <thead>
        <tr>
          <th>time</th>
          <th>rule</th>
          <th>level</th>
          <th>description</th>
          <th>mitre</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e, i) => (
          <tr key={`${e.row_id}-${e.rid}-${i}`}>
            <td>{e.ts || e.ts_raw || ''}</td>
            <td>{e.rid || ''}</td>
            <td className={SEV_CLASS[e.level] || ''}>{LEVEL_EN[e.level] || ''}</td>
            <td>{e.descr || ''}</td>
            <td>
              <MitreTags list={e.mitre} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
