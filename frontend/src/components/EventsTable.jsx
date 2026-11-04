import { useCallback, useState } from 'react'
import { getEvents } from '../api.js'
import { LEVEL_EN, SEV_CLASS, fmtNum } from '../format.js'
import { Empty, MitreTags } from './common.jsx'
import ProfilePanel from './ProfilePanel.jsx'
import VirtualBody from './VirtualBody.jsx'
import { useVirtualRows } from './useVirtualRows.js'

/** Every event of the case in one scrolling box whose scrollbar stands for all of
 *  them from the start (the user, 2026-11-02: scroll, not load more). A case can
 *  hold 65k+ rows and 25k findings, so the client never asks for the whole table:
 *  only the rows in view are drawn, and the server pages they fall in are fetched
 *  as they come into view (useVirtualRows). FR-11.2: every event of the case by
 *  default, the rule matches one click away. `order` "time" is the Timeline step:
 *  every event by event time, then row, and the rule matches too (file order is
 *  "row", where the matches come most severe first). */
export default function EventsTable({ caseId, order = 'row' }) {
  const [flagged, setFlagged] = useState(false)
  // The behaviour profile open above the table, if any: { kind, value }.
  const [profile, setProfile] = useState(null)
  // The event-time window applied: { since, until }, GMT+7, '' = open at that end.
  const [win, setWin] = useState({ since: '', until: '' })
  const [winError, setWinError] = useState('')

  const fetchPage = useCallback(
    (offset, limit) => getEvents(caseId, { limit, offset, flagged, order, ...win }),
    [caseId, flagged, order, win],
  )
  const v = useVirtualRows(fetchPage, (d) => d.events, `${caseId}|${flagged}|${order}|${win.since}|${win.until}`)
  const data = v.meta

  const showProfile = (kind, value) => setProfile({ kind, value })

  // Read from the form at submit, like the login page: the inputs are uncontrolled,
  // and `key` gives them fresh defaults when the window is cleared.
  function applyWindow(e) {
    e.preventDefault()
    // With step=1 the browser drops ":00" seconds from the value; put them back, or
    // "To 10:15:00" would be read as the whole minute (routers/cases.py _when).
    const full = (val) => (val && val.length === 16 ? `${val}:00` : val)
    const since = full(e.currentTarget.elements.since.value)
    const until = full(e.currentTarget.elements.until.value)
    if (since && until && since > until) {
      setWinError('"From" is after "To"')
      return
    }
    setWinError('')
    setWin({ since, until })
  }

  function clearWindow() {
    setWinError('')
    setWin({ since: '', until: '' })
  }

  const windowed = !!(win.since || win.until)
  const first = toLocalInput(data?.ts_first)
  const last = toLocalInput(data?.ts_last)

  const toggle = (
    <div className="ov-filters">
      <button type="button" className={`chip-btn${flagged ? '' : ' active'}`} onClick={() => setFlagged(false)}>
        All events
      </button>
      <button type="button" className={`chip-btn${flagged ? ' active' : ''}`} onClick={() => setFlagged(true)}>
        Flagged only
      </button>
      {/* The event-time window (GMT+7, as every time on the page); both ends inclusive. */}
      <form className="time-window" onSubmit={applyWindow} key={`${win.since}|${win.until}`}>
        <span className="tw-field">
          <label htmlFor="tw-since">From</label>
          <input id="tw-since" name="since" type="datetime-local" step="1" defaultValue={win.since}
                 min={first} max={last} />
        </span>
        <span className="tw-field">
          <label htmlFor="tw-until">To</label>
          <input id="tw-until" name="until" type="datetime-local" step="1" defaultValue={win.until}
                 min={first} max={last} />
        </span>
        <span className="cell-sub">GMT+7</span>
        <button type="submit" className="secondary">Filter</button>
        {windowed && (
          <button type="button" className="secondary" onClick={clearWindow}>
            Clear
          </button>
        )}
        {winError && <span className="status-line err">{winError}</span>}
      </form>
    </div>
  )
  const between = windowed
    ? ` between ${win.since ? win.since.replace('T', ' ') : 'the first event'} and ${win.until ? win.until.replace('T', ' ') : 'the last'}`
    : ''

  let body
  if (v.error && !data) body = <Empty>Could not load: {v.error}</Empty>
  else if (!data) body = <Empty>Loading...</Empty>
  else if (!v.total) {
    body = (
      <Empty>
        {windowed
          ? `No ${flagged ? 'flagged ' : ''}events${between}`
          : flagged
            ? 'The rule engine flagged nothing in this file'
            : 'No events in this file'}
      </Empty>
    )
  } else {
    body = (
      <>
        <Empty style={{ paddingBottom: 8 }}>
          {/* Flagged: a line per rule match - an event two rules matched is two lines
              (gotcha #6), so the lines outnumber the events flagged. */}
          {flagged
            ? `${fmtNum(v.total)} rule matches on ${fmtNum(data.flagged_count)} of ${fmtNum(data.total_rows)} events${between}, ${order === 'time' ? 'in time order' : 'most severe first'}`
            : `${fmtNum(v.total)} events${between} (${fmtNum(data.flagged_count)} flagged)`}
          {/* A window can only hold an event whose time was read (db.time_window). */}
          {windowed ? ' - events with no readable time are left out' : ''}
          {v.error ? ` - could not load some of them: ${v.error}` : ''}
        </Empty>
        {/* One line a row; the box scrolls both ways and its scrollbar is the whole list. */}
        <div className="events-scroll" ref={v.box} onScroll={v.onScroll}>
          {flagged ? <FlaggedRows v={v} onProfile={showProfile} /> : <AllRows v={v} onProfile={showProfile} />}
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

/** "2020-11-03 22:50:18.511369+07:00" (how the API writes a time) as a
 *  datetime-local value, "2020-11-03T22:50:18" - the zone is GMT+7 on both sides. */
function toLocalInput(ts) {
  if (!ts) return undefined
  const m = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})/.exec(ts)
  return m ? `${m[1]}T${m[2]}` : undefined
}

/** SigmaHQ rules that mark this event without making it a suggestion - medium and below,
 *  threat hunting, or the twin of one of our rules (docs/specs/sigma_windows.md S-D4, S-D7).
 *  Each names its author, as the Detection Rule License 1.1 asks of every match.
 *  Beside the event type, on its line: every row of the list is one line high. */
function SigmaMarks({ marks }) {
  if (!marks || !marks.length) return null
  return (
    <span className="sigma-marks">
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
    </span>
  )
}

function AllRows({ v, onProfile }) {
  return (
    <table className="events-table vlist">
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
      <VirtualBody
        v={v}
        cols={10}
        row={(e, i, ref) => (
          <tr key={i} ref={ref} data-i={i}>
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
        )}
      />
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
function FlaggedRows({ v, onProfile }) {
  return (
    <table className="events-table vlist">
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
      <VirtualBody
        v={v}
        cols={10}
        row={(e, i, ref) => (
          <tr key={i} ref={ref} data-i={i}>
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
        )}
      />
    </table>
  )
}
