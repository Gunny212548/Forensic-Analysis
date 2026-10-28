import { useState } from 'react'
import { LEVEL_EN, fmtNum } from '../format.js'

/** Confirmed finding groups as an attack timeline: the ATT&CK tactics they reach as
 *  a row of stages, in ATT&CK's order - only the tactics found, the user's choice of
 *  2026-10-22 - and below, every group in the order its first event happened. A stage
 *  filters the list. `rows` come sorted by first event; `findingHref(f)` opens one.
 *  With `showCase`, each row names the case it is in - a project's timeline spans its
 *  cases (specs/projects.md P4). Shared by a case's Attack timeline step and a
 *  project's. */
export default function AttackTimelineView({ rows, tacticOrder, findingHref, showCase = false }) {
  const [stage, setStage] = useState('')
  const names = Object.fromEntries((tacticOrder || []).map((t) => [t.id, t.name]))
  const stagesOf = (f) => (f.tactics?.length ? f.tactics : ['unmapped'])
  // The stages reached, in ATT&CK's order, then the groups no technique maps.
  const stages = [...(tacticOrder || []).map((t) => t.id), 'unmapped']
    .map((id) => {
      const members = rows.filter((f) => stagesOf(f).includes(id))
      return members.length ? { id, name: names[id] || 'Not mapped to ATT&CK', members, first: members[0].ts_first } : null
    })
    .filter(Boolean)
  const shown = stage ? rows.filter((f) => stagesOf(f).includes(stage)) : rows
  return (
    <>
      <div className="tl-stages" role="tablist" aria-label="ATT&CK tactics reached">
        {stages.map((st) => (
          <button
            type="button"
            key={st.id}
            role="tab"
            aria-selected={stage === st.id}
            className={`tl-stage ${stage === st.id ? 'tl-stage-on' : ''} ${st.id === 'unmapped' ? 'tl-stage-unmapped' : ''}`}
            title={stage === st.id ? 'Show every stage' : `Show only ${st.name}`}
            onClick={() => setStage(stage === st.id ? '' : st.id)}
          >
            <span className="tl-stage-name">{st.name}</span>
            <span className="tl-stage-sub">
              {st.first ? st.first.slice(0, 10) : 'no time'} · {st.members.length} group{st.members.length === 1 ? '' : 's'}
            </span>
          </button>
        ))}
      </div>
      <div className="muted tl-note">
        Stages are the ATT&amp;CK Enterprise tactics (v20) of the confirmed groups&apos; techniques, in ATT&amp;CK&apos;s order -
        not the order they happened; that is the list below.
        {stage && (
          <>
            {' '}
            <button type="button" className="link-button" onClick={() => setStage('')}>Show every stage</button>
          </>
        )}
      </div>
      <div className="table-scroll">
        <table className="ov-table">
          <thead>
            <tr>
              <th>First event</th>
              <th>Last event</th>
              <th>Stage</th>
              <th>What happened</th>
              {showCase && <th>Case</th>}
              <th>ATT&amp;CK</th>
              <th>Events</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((f) => (
              <tr key={`${f.case_id || ''}|${f.key}`}>
                <td className="mono">{f.ts_first || ''}</td>
                <td className="mono">{f.ts_last && f.ts_last !== f.ts_first ? f.ts_last : ''}</td>
                <td>{stagesOf(f).map((t) => names[t] || 'Not mapped').join(', ')}</td>
                <td>
                  <a className="table-link" href={findingHref(f)}>
                    {f.descr}
                  </a>
                  <div className="cell-sub">
                    {f.fd || f.rid} · {LEVEL_EN[f.level] || f.level}
                  </div>
                </td>
                {showCase && (
                  <td>
                    <a className="table-link" href={`#/case/${f.case_id}/attack-timeline`}>{f.case_file || f.case_id}</a>
                  </td>
                )}
                <td>{(f.mitre || []).join(', ')}</td>
                <td>{fmtNum(f.cnt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}
