import { useCallback, useEffect, useState } from 'react'
import { getEvents } from '../api.js'
import { LEVEL_EN, SEV_CLASS, fmtNum } from '../format.js'
import { Empty, MitreTags } from './common.jsx'
import ProfilePanel from './ProfilePanel.jsx'

const PAGE_SIZE = 100

/** Paginated, server-side. A case can hold 65k+ rows and 25k findings, so
 *  the client never pulls the whole table - the offset lives here and every
 *  page is its own query. FR-11.2: every event of the case by default, the
 *  rule matches one click away. `order` "time" is the Timeline step: every
 *  event by event time, then row, and the rule matches too (file order is "row",
 *  where the matches come most severe first). */
export default function EventsTable({ caseId, order = 'row' }) {
  const [flagged, setFlagged] = useState(false)
  const [offset, setOffset] = useState(0)
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  // The behaviour profile open above the table, if any: { kind, value }.
  const [profile, setProfile] = useState(null)

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

  const showProfile = (kind, value) => setProfile({ kind, value })

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
          {/* Flagged: a line per rule match - an event two rules matched is two lines
              (gotcha #6), so the lines outnumber the events flagged. */}
          {flagged
            ? `Showing ${fmtNum(from)}-${fmtNum(to)} of ${fmtNum(data.total)} rule matches on ${fmtNum(data.flagged_count)} of ${fmtNum(data.total_rows)} events, ${order === 'time' ? 'in time order' : 'most severe first'}`
            : `Showing ${fmtNum(from)}-${fmtNum(to)} of ${fmtNum(data.total)} events (${fmtNum(data.flagged_count)} flagged)`}
        </Empty>
        {/* One line a row, the box scrolls both ways (styles.css .events-scroll). */}
        <div className="events-scroll">
          {flagged ? (
            <FlaggedRows events={data.events} onProfile={showProfile} />
          ) : (
            <AllRows events={data.events} onProfile={showProfile} />
          )}
        </div>
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
      {profile && (
        <ProfilePanel caseId={caseId} kind={profile.kind} value={profile.value} onClose={() => setProfile(null)} />
      )}
      {body}
    </>
  )
}

/** SigmaHQ rules that mark this event without making it a suggestion - medium and below,
 *  threat hunting, or the twin of one of our rules (specs/sigma_windows.md S-D4, S-D7).
 *  Each names its author, as the Detection Rule License 1.1 asks of every match. */
function SigmaMarks({ marks }) {
  if (!marks || !marks.length) return null
  return (
    <div className="sigma-marks">
      {marks.map((m) => (
        <a
          key={m.rid}
          href={m.url}
          target="_blank"
          rel="noreferrer noopener"
          className={`sigma-mark sev-tag sev-tag-${m.level}`}
          title={`SigmaHQ rule by ${m.author || 'unknown author'} (Detection Rule License 1.1)` +
            (m.twin_of ? ` - the same events ${m.twin_of} decides` : '')}
        >
          {m.title}
        </a>
      ))}
    </div>
  )
}

function AllRows({ events, onProfile }) {
  return (
    <table className="events-table">
      <thead>
        <tr>
          <th>time</th>
          <WhoHeads />
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
            <WhoCells e={e} onProfile={onProfile} />
            {/* Layer A: the event type, named by the server (db.EVENT_TYPES)
                so the table and the MCP tools use the same words. */}
            <td>
              {e.event || ''}
              <SigmaMarks marks={e.sigma} />
            </td>
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
            {/* The whole record on one line - the box scrolls sideways to it. */}
            <td className="raw-cell">{e.raw || ''}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/** Where an event happened and who was in it - the same four columns in both tables. */
function WhoHeads() {
  return (
    <>
      <th title="The computer or device that wrote this record - a Windows event's Computer, a syslog line's host, a FortiGate's devname. Not the destination.">
        host
      </th>
      <th>source</th>
      <th>destination</th>
      <th>account</th>
    </>
  )
}

function WhoCells({ e, onProfile }) {
  return (
    <>
      {/* The machine that logged it (raw_events.hostname); empty where the log has none. */}
      <td className="mono">{e.hostname || ''}</td>
      <td>
        {/* Opens the address's or account's behaviour profile above the table. */}
        {e.srcip ? (
          <button type="button" className="link-btn mono" onClick={() => onProfile('source', e.srcip)}>
            {e.srcip}
          </button>
        ) : (
          ''
        )}
      </td>
      <td>{e.dstip || ''}</td>
      <td>
        {e.username ? (
          <button type="button" className="link-btn mono" onClick={() => onProfile('account', e.username)}>
            {e.username}
          </button>
        ) : (
          ''
        )}
      </td>
    </>
  )
}

/** One line per rule match: the event's time, where and who, then what the rule said. */
function FlaggedRows({ events, onProfile }) {
  return (
    <table className="events-table">
      <thead>
        <tr>
          <th>time</th>
          <WhoHeads />
          <th>rule</th>
          <th>level</th>
          <th>description</th>
          <th>mitre</th>
          <th>raw message</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e, i) => (
          <tr key={`${e.row_id}-${e.rid}-${i}`}>
            <td>{e.ts || e.ts_raw || ''}</td>
            <WhoCells e={e} onProfile={onProfile} />
            <td className="mono">{e.rid || ''}</td>
            <td className={SEV_CLASS[e.level] || ''}>{LEVEL_EN[e.level] || ''}</td>
            <td>{e.descr || ''}</td>
            <td>
              <MitreTags list={e.mitre} />
            </td>
            <td className="raw-cell">{e.raw || ''}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
