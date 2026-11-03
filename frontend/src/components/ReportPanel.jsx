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
 *  a new version with its SHA-256; the analyst's final may be uploaded back (R-D4). */
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
  const finalRef = useRef(null)
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
    const fields = {}
    for (const k of ['details', 'author_position', 'approver_name', 'approver_position',
      'coordinator_name', 'coordinator_position']) fields[k] = f[k].value.trim()
    setBusy('draft')
    setError('')
    setDone('')
    try {
      let pictures = { png: null, svg: null }
      const svg = graphRef.current?.querySelector('svg')
      if (svg) pictures = await exportSvg(svg)
      const line = await makeReportDraft(co, pj, fields, pictures.png, pictures.svg)
      setDone(`Draft ${line.version} made`)
      f.details.value = ''
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy('')
    }
  }

  async function addFinal(e) {
    e.preventDefault()
    const f = finalRef.current.elements
    const file = f.file.files[0]
    if (!file) {
      setError('Choose the final file (.docx or .pdf)')
      return
    }
    setBusy('final')
    setError('')
    setDone('')
    try {
      const line = await uploadReportFinal(co, pj, f.version.value, file)
      setDone(`Final kept as ${line.file}`)
      f.file.value = ''
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy('')
    }
  }

  const gate = data?.gate
  const drafts = data?.drafts || []
  const finals = data?.finals || []
  const edges = graph?.graph?.edges || []
  return (
    <Section icon="report" tone={drafts.length ? 'ok' : 'muted'}
             title={fromCase ? `Report of ${project.name || 'the project'}` : 'Report'}
             sub={(fromCase ? 'One report per project, from every case in it · ' : '')
               + (!data ? '' : `${drafts.length} ${drafts.length === 1 ? 'draft' : 'drafts'}`
               + ` · ${finals.length} ${finals.length === 1 ? 'final' : 'finals'} uploaded`)}>
      <div className="cp-section-body">
        {error && <div className="lc-error">{error}</div>}
        {done && <div className="status-line">{done}</div>}
        {!data ? (
          <div className="empty">{error ? '' : 'Loading...'}</div>
        ) : (
          <>
            <div className={`rv-gate ${gate.open ? 'ok' : 'blocked'}`}>
              {gate.open
                ? `Every suggestion is decided (${gate.confirmed} confirmed) - a draft can be made.`
                : <>A draft waits for: {gate.reasons.join('; ')}.</>}
            </div>

            <form ref={formRef} className="lc-form report-form" onSubmit={makeDraft}>
              <div className="section-label">Make draft {data.next_version}</div>
              <p className="cell-sub">
                A Word file from the report skeleton: every section from the confirmed findings, the
                Executive Summary drafted by the AI and highlighted for you to check, the attack path
                below as its picture. Finish and sign it in Word.
              </p>
              <label>
                What changed in this version
                <input name="details" maxLength={500} placeholder="e.g. first draft for review" />
              </label>
              <label>
                Your position (author)
                <input name="author_position" maxLength={200} placeholder="e.g. Forensic Analyst" />
              </label>
              <label>
                Reviewer / approver
                <input name="approver_name" maxLength={200} placeholder="name - or leave blank, fill in Word" />
              </label>
              <label>
                Approver&apos;s position
                <input name="approver_position" maxLength={200} />
              </label>
              <label>
                Project coordinator
                <input name="coordinator_name" maxLength={200} placeholder="name - or leave blank" />
              </label>
              <label>
                Coordinator&apos;s position
                <input name="coordinator_position" maxLength={200} />
              </label>
              <div className="lc-actions">
                <button type="submit" disabled={!gate.open || !mayMake || !!busy}
                        title={!mayMake ? why('case:analyze') : undefined}>
                  {busy === 'draft' ? 'Making the draft - the AI writes the summary (about 15 s)...' : `Make draft ${data.next_version}`}
                </button>
                {gate.open && !edges.length && <span className="cell-sub">No attack path to picture - the draft says so</span>}
              </div>
            </form>

            <div className="section-label">Drafts</div>
            <div className="table-scroll">
              <table className="ov-table">
                <thead>
                  <tr>
                    <th>Version</th>
                    <th>Made</th>
                    <th>By</th>
                    <th>What changed</th>
                    <th>AI summary</th>
                    <th>SHA-256</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {!drafts.length && (
                    <tr>
                      <td colSpan={7} className="empty">No draft made yet</td>
                    </tr>
                  )}
                  {drafts.slice().reverse().map((d) => (
                    <tr key={d.file}>
                      <td className="mono">{d.version}</td>
                      <td className="cell-sub">{fmtTime(d.ts)}</td>
                      <td>{d.actor_name || d.actor}</td>
                      <td>{d.details || <span className="muted">—</span>}</td>
                      <td className="cell-sub">
                        {d.summary?.error
                          ? `not drafted: ${d.summary.error}`
                          : `${d.summary?.kept ?? 0} paragraphs` + (d.summary?.refused ? `, ${d.summary.refused} refused` : '')}
                      </td>
                      <td className="mono cell-sub" title={d.sha256}>{d.sha256?.slice(0, 16)}</td>
                      <td>
                        <a href={reportFileUrl(co, pj, d.file)} download>Download .docx</a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="section-label">Finals uploaded back (not required)</div>
            <div className="table-scroll">
              <table className="ov-table">
                <thead>
                  <tr>
                    <th>From draft</th>
                    <th>Uploaded</th>
                    <th>By</th>
                    <th>File</th>
                    <th>Size</th>
                    <th>SHA-256</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {!finals.length && (
                    <tr>
                      <td colSpan={7} className="empty">None - a final is kept here only if someone uploads it</td>
                    </tr>
                  )}
                  {finals.slice().reverse().map((f) => (
                    <tr key={f.file}>
                      <td className="mono">{f.version}</td>
                      <td className="cell-sub">{fmtTime(f.ts)}</td>
                      <td>{f.actor}</td>
                      <td>{f.original_name || f.file}</td>
                      <td className="cell-sub">{fmtBytes(f.bytes)}</td>
                      <td className="mono cell-sub" title={f.sha256}>{f.sha256?.slice(0, 16)}</td>
                      <td>
                        <a href={reportFileUrl(co, pj, f.file)} download>Download</a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {drafts.length > 0 && mayMake && (
              <form ref={finalRef} className="lc-form report-form" onSubmit={addFinal}>
                <label>
                  Final of draft
                  <select name="version" defaultValue={drafts[drafts.length - 1].version}>
                    {drafts.slice().reverse().map((d) => (
                      <option key={d.version} value={d.version}>{d.version}</option>
                    ))}
                  </select>
                </label>
                <label>
                  File (.docx or .pdf)
                  <input type="file" name="file" accept=".docx,.pdf" />
                </label>
                <div className="lc-actions">
                  <button type="submit" className="secondary" disabled={!!busy}>
                    {busy === 'final' ? 'Uploading...' : 'Upload final'}
                  </button>
                </div>
              </form>
            )}
          </>
        )}
        {/* The picture the draft carries: drawn here, out of sight, so it can be taken
            even when the Attack path section above is folded. */}
        {edges.length > 0 && (
          <div ref={graphRef} className="report-graph-source" aria-hidden="true">
            <AttackGraph graph={graph.graph} />
          </div>
        )}
      </div>
    </Section>
  )
}
