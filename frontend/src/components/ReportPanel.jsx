import { useCallback, useEffect, useRef, useState } from 'react'
import { getProjectGraph, getReport, makeReportDraft, reportFileUrl, uploadReportFinal } from '../api.js'
import { fmtBytes, fmtTime } from '../format.js'
import { useAccess } from '../permissions.js'
import AttackGraph from './AttackGraph.jsx'
import { Section } from './cards.jsx'
import { exportSvg } from './svgExport.js'

/** The project's forensic report (specs/forensic_report.md, IAI-72 / IAI-73).
 *  The system makes a draft - a Word file the analyst finishes in Word - only once every
 *  suggestion of the project is decided (R-D2; no question required). Each draft is
 *  a new version with its SHA-256; the analyst's final may be uploaded back (R-D4).
 *
 *  Laid out newest draft first (the user's choice, 2026-11-03 - the form-first layout was
 *  "hard to use"): the latest draft with Download and Upload final, then Make the next one
 *  with only "what changed" open - the cover-page names fold, filled in from the last
 *  draft - then the earlier versions and every final, folded. */

const PEOPLE = [
  ['author_position', 'Your position (author)', 'e.g. Forensic Analyst'],
  ['approver_name', 'Reviewer / approver', 'name - or leave blank, fill in Word'],
  ['approver_position', "Approver's position", ''],
  ['coordinator_name', 'Project coordinator', 'name - or leave blank'],
  ['coordinator_position', "Coordinator's position", ''],
]

function aiLine(d) {
  const s = d.summary || {}
  if (s.error) return `AI did not draft: ${s.error}`
  const parts = [`${s.kept ?? 0} summary paragraphs` + (s.refused ? ` (${s.refused} cut by the check)` : '')]
  if (s.recommendations != null) {
    parts.push(`${s.recommendations} recommendations`
      + (s.recommendations_refused ? ` (${s.recommendations_refused} cut)` : ''))
  }
  return `AI: ${parts.join(' · ')}`
}

/** Upload the analyst's final of one draft: the button opens the file picker and the
 *  chosen file goes straight up - no separate form to fill. */
function FinalUpload({ co, pj, version, busy, onStart, onDone, onError }) {
  const input = useRef(null)
  async function chosen(e) {
    const file = e.target.files[0]
    e.target.value = ''
    if (!file) return
    onStart()
    try {
      const line = await uploadReportFinal(co, pj, version, file)
      onDone(`Final of ${version} kept as ${line.file}`)
    } catch (err) {
      onError(err.message)
    }
  }
  return (
    <>
      <input ref={input} type="file" accept=".docx,.pdf" hidden onChange={chosen} />
      <button type="button" className="secondary" disabled={!!busy}
              title="The signed / finished file (.docx or .pdf) - not required"
              onClick={() => input.current.click()}>
        {busy === 'final' ? 'Uploading...' : 'Upload final...'}
      </button>
    </>
  )
}

function FinalsOf({ co, pj, finals }) {
  if (!finals.length) return null
  return (
    <div className="rp-finals">
      Final{finals.length > 1 ? 's' : ''}:{' '}
      {finals.map((f, i) => (
        <span key={f.file}>
          {i > 0 && ' · '}
          <a href={reportFileUrl(co, pj, f.file)} download title={`SHA-256 ${f.sha256}`}>
            {f.original_name || f.file}
          </a>{' '}
          <span className="cell-sub">{fmtBytes(f.bytes)} · {f.actor} · {fmtTime(f.ts)}</span>
        </span>
      ))}
    </div>
  )
}

export default function ReportPanel({ project, fromCase = false }) {
  const { can, why } = useAccess()
  const co = project.company_id
  const pj = project.project_id
  const [data, setData] = useState(null)
  const [graph, setGraph] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [done, setDone] = useState('')
  const formRef = useRef(null)
  const graphRef = useRef(null)

  const load = useCallback(async () => {
    try {
      const [r, g] = await Promise.all([getReport(co, pj), getProjectGraph(co, pj)])
      setData(r)
      setGraph(g)
      setError('')
    } catch (err) {
      setError(err.message)
    }
  }, [co, pj])
  useEffect(() => {
    load()
  }, [load])

  const mayMake = can('case:analyze')

  async function makeDraft(e) {
    e.preventDefault()
    // Read at click time (autofill fires no input events - CLAUDE.md, Login.jsx).
    const f = formRef.current.elements
    const fields = { details: f.details.value.trim() }
    for (const [k] of PEOPLE) fields[k] = f[k].value.trim()
    setBusy('draft')
    setError('')
    setDone('')
    try {
      let pictures = { png: null, svg: null }
      const svg = graphRef.current?.querySelector('svg')
      if (svg) pictures = await exportSvg(svg)
      const line = await makeReportDraft(co, pj, fields, pictures.png, pictures.svg)
      setDone(`Draft ${line.version} made - download it above`)
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy('')
    }
  }

  const finalHandlers = {
    onStart: () => {
      setBusy('final')
      setError('')
      setDone('')
    },
    onDone: async (msg) => {
      setDone(msg)
      setBusy('')
      await load()
    },
    onError: (msg) => {
      setError(msg)
      setBusy('')
    },
  }

  const gate = data?.gate
  const drafts = data?.drafts || []
  const finals = data?.finals || []
  const latest = drafts[drafts.length - 1]
  const earlier = drafts.slice(0, -1).reverse()
  const finalsOf = (v) => finals.filter((f) => f.version === v).slice().reverse()
  const people = latest?.people || {}
  const named = PEOPLE.filter(([k]) => people[k]).length
  const edges = graph?.graph?.edges || []

  const sub = !data ? '' : gate.open
    ? `Ready - ${gate.confirmed} confirmed finding${gate.confirmed === 1 ? '' : 's'}`
      + (fromCase ? ' · one report per project, from every case in it' : '')
    : 'Waiting - see below'
  return (
    <Section icon="report" tone={drafts.length ? 'ok' : gate && !gate.open ? 'warn' : 'muted'}
             title={fromCase ? `Report of ${project.name || 'the project'}` : 'Report'} sub={sub}>
      <div className="cp-section-body rp">
        {error && <div className="lc-error">{error}</div>}
        {done && <div className="status-line">{done}</div>}
        {!data ? (
          <div className="empty">{error ? '' : 'Loading...'}</div>
        ) : (
          <>
            {!gate.open && <div className="rv-gate blocked">A draft waits for: {gate.reasons.join('; ')}.</div>}

            {latest ? (
              <div className="rp-latest">
                <div className="rp-latest-head">
                  <span className="rp-kicker">Latest draft</span>
                  <span className="rp-version mono">{latest.version}</span>
                  <span className="cell-sub">{fmtTime(latest.ts)} · {latest.actor_name || latest.actor}</span>
                </div>
                {/* Not the typed "what changed": it is the Thai draft's change-log text, and the
                    page is English (the user, 2026-11-03) - it is in the file's change log. */}
                <div className="cell-sub">{aiLine(latest)}</div>
                <div className="lc-actions rp-actions">
                  <a className="btn-primary" href={reportFileUrl(co, pj, latest.file)} download>
                    Download {latest.version} (.docx)
                  </a>
                  {mayMake && <FinalUpload co={co} pj={pj} version={latest.version} busy={busy} {...finalHandlers} />}
                  <span className="mono cell-sub" title={`SHA-256 ${latest.sha256}`}>
                    SHA-256 {latest.sha256?.slice(0, 16)}...
                  </span>
                </div>
                <FinalsOf co={co} pj={pj} finals={finalsOf(latest.version)} />
              </div>
            ) : (
              <div className="empty rp-none">No draft yet. Make the first one below - it takes about half a minute.</div>
            )}

            {/* Keyed on the latest version, so the names it was made with come back as the
                defaults once a new draft is in. */}
            <form key={latest?.version || 'none'} ref={formRef} className="rp-make" onSubmit={makeDraft}>
              <div className="rp-make-row">
                <label className="rp-field">
                  <span>
                    What changed in {data.next_version}{' '}
                    <span className="cell-sub">- goes into the Word draft&apos;s change log only (the draft is written in Thai)</span>
                  </span>
                  <input type="text" name="details" maxLength={500}
                         placeholder={latest ? 'e.g. corrected after review' : 'e.g. first draft for review'} />
                </label>
                <button type="submit" disabled={!gate.open || !mayMake || !!busy}
                        title={!mayMake ? why('case:analyze') : !gate.open ? 'Every suggestion must be decided first' : undefined}>
                  {busy === 'draft' ? 'Making - the AI is writing (about 30 s)...' : `Make draft ${data.next_version}`}
                </button>
              </div>
              <details className="rp-fold">
                <summary>
                  Names on the cover page
                  <span className="cell-sub">
                    {' '}- {named ? `${named} filled in from draft ${latest.version}` : 'optional, or fill them in Word'}
                  </span>
                </summary>
                <div className="rp-people">
                  {PEOPLE.map(([k, label, ph]) => (
                    <label className="rp-field" key={k}>
                      {label}
                      <input type="text" name={k} maxLength={200} placeholder={ph} defaultValue={people[k] || ''} />
                    </label>
                  ))}
                </div>
              </details>
              <div className="cell-sub rp-note">
                A Word file from the report skeleton: every section from the confirmed findings, the
                Executive Summary and the recommendations drafted by the AI and highlighted for you to
                check{edges.length ? ', the attack path as its picture' : ' - no attack path to picture, the draft says so'}.
                Finish and sign it in Word.
              </div>
            </form>

            {(earlier.length > 0 || finals.length > 0) && (
              <details className="rp-fold rp-history">
                <summary>
                  Earlier versions ({earlier.length}) · finals uploaded ({finals.length})
                </summary>
                <div className="table-scroll">
                  <table className="ov-table">
                    <thead>
                      <tr>
                        <th>Version</th>
                        <th>Made</th>
                        <th>By</th>
                        <th>AI</th>
                        <th>Finals</th>
                        <th />
                      </tr>
                    </thead>
                    <tbody>
                      {earlier.map((d) => (
                        <tr key={d.file}>
                          <td className="mono" title={`SHA-256 ${d.sha256}`}>{d.version}</td>
                          <td className="cell-sub">{fmtTime(d.ts)}</td>
                          <td>{d.actor_name || d.actor}</td>
                          <td className="cell-sub">{aiLine(d).replace(/^AI: /, '')}</td>
                          <td><FinalsOf co={co} pj={pj} finals={finalsOf(d.version)} /></td>
                          <td className="rp-row-actions">
                            <a href={reportFileUrl(co, pj, d.file)} download>Download</a>
                            {mayMake && <FinalUpload co={co} pj={pj} version={d.version} busy={busy} {...finalHandlers} />}
                          </td>
                        </tr>
                      ))}
                      {!earlier.length && (
                        <tr>
                          <td colSpan={6} className="empty">Only the latest draft so far</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </details>
            )}
          </>
        )}
        {/* The picture the draft carries: drawn here, out of sight, so it can be taken
            even when the Attack path section is folded. */}
        {edges.length > 0 && (
          <div ref={graphRef} className="report-graph-source" aria-hidden="true">
            <AttackGraph graph={graph.graph} />
          </div>
        )}
      </div>
    </Section>
  )
}
