import { useCallback, useEffect, useRef, useState } from 'react'
import { getAnalysis, getCase, getFindings, getFlow, getGraph, runAnalysis } from '../api.js'
import { LEVEL_EN, fmtNum, fmtTime, statusOf } from '../format.js'
import { Empty, SeverityPill } from '../components/common.jsx'
import StepBar, { stepHref } from '../components/StepBar.jsx'
import EventsTable from '../components/EventsTable.jsx'
import ReviewPanel from '../components/ReviewPanel.jsx'
import AttackGraph from '../components/AttackGraph.jsx'
import MappingNote from '../components/Mapping.jsx'
import Evidence from '../components/Evidence.jsx'
import Veris from '../components/Veris.jsx'
import {
  AnalysisMeta,
  AnalysisProgress,
  ChainFlow,
  ChainStages,
  Recommendations,
  RiskTables,
  Timeline,
} from '../components/analysis.jsx'

/** The case page: one case as six steps (specs/case_flow_design.md), at
 *  #/case/<id>/<step>. It replaced the Reports / Attack Graph / Timeline pages,
 *  whose links redirect here (App.jsx). Each step shows the components those
 *  pages had, moved rather than rewritten; what a step's state is comes from
 *  the server (GET /flow), never from this page. */

// A queued map-reduce job runs for minutes (about one model call a minute),
// so the page polls rather than holding one request open. 4s is often enough
// to see a batch tick over and cheap enough to leave running.
const POLL_MS = 4000

// The server stops reporting a job that has not written progress for 15
// minutes and answers the poll with the older analysis or a 404 instead. A
// map call can outlast that window and the job then reappears, so an empty
// poll is not the end of the job - but after a minute of them the progress on
// screen is no longer confirmed by anything, and the panel says so.
const STALL_POLLS = 15

/** Split any /analyze or /analysis body into the three things the page
 *  renders: a finished report, a running job, a failure reason.
 *
 *  Both in-progress answers are 2xx, so the HTTP code says nothing - the body
 *  does. When a job is running the server returns either the OLD finished
 *  analysis (fully renderable, just stale) or a stub whose arrays are empty
 *  and whose `summary` is a progress sentence. `_meta` is written by the
 *  analysis pipeline and never by the job view, so it is what tells the two
 *  apart; rendering the stub as a report is exactly the bug this avoids. */
export function readAnalysis(body) {
  if (!body) return { report: null, job: null, failed: '' }
  const status = body.analysis_status
  if (status === 'failed') {
    return { report: null, job: null, failed: body.summary || 'The analysis failed' }
  }
  if (status === 'running') {
    // `already_running` sits on the envelope, not the job record, but it is
    // about the job - carry it along so the progress panel can say so.
    const job = body.analysis_job
      ? { ...body.analysis_job, already_running: !!body.already_running }
      : null
    return { report: body._meta ? body : null, job, failed: '' }
  }
  // "ready", or a pre-map-reduce body with no status at all: unchanged.
  return { report: body, job: null, failed: '' }
}

/** The AI analysis of one case: the cached narrative, a running job and its
 *  polling, and starting one. `onSettled` is called when a run ends, so the
 *  step bar can be asked again. */
function useAnalysis(caseId, ready, onSettled) {
  const [analysis, setAnalysis] = useState(null)
  const [job, setJob] = useState(null)
  const [jobFailed, setJobFailed] = useState('')
  const [stalled, setStalled] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [analyzeError, setAnalyzeError] = useState('')

  // One place decides what a body means, so the POST answer and every poll
  // answer are treated identically.
  const apply = useCallback((body) => {
    const { report, job: next, failed } = readAnalysis(body)
    // A running job with no cached analysis must not blank a report that is
    // already on screen (the poll body simply has nothing better to offer).
    if (report) setAnalysis(report)
    setJob(next)
    setJobFailed(failed)
    setStalled(false)
  }, [])

  useEffect(() => {
    if (!ready) return undefined
    let alive = true
    getAnalysis(caseId)
      .then((a) => alive && apply(a))
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [caseId, ready, apply])

  // Polls only while a job is in flight; torn down on unmount and as soon as a
  // poll comes back ready/failed, which clears `job`. Depends on the boolean,
  // not the job object, so a progress update does not restart the timer.
  const polling = !!job
  const emptyPolls = useRef(0)
  useEffect(() => {
    if (!polling) return undefined
    let alive = true
    emptyPolls.current = 0
    const t = setInterval(async () => {
      let body = null
      try {
        body = await getAnalysis(caseId)
      } catch {
        // network blip - treated like an empty answer, the next tick retries
      }
      if (!alive) return
      if (body) {
        emptyPolls.current = 0
        apply(body)
      } else {
        emptyPolls.current += 1
        if (emptyPolls.current >= STALL_POLLS) setStalled(true)
      }
    }, POLL_MS)
    return () => {
      alive = false
      clearInterval(t)
      onSettled?.()
    }
  }, [polling, caseId, apply, onSettled])

  const analyze = useCallback(
    async (force) => {
      setAnalyzing(true)
      setAnalyzeError('')
      setJobFailed('')
      try {
        // 200 = the narrative (small case). 202 = a map-reduce job was queued
        // instead; the polling effect above takes it from here.
        apply(await runAnalysis(caseId, force))
      } catch (err) {
        // 429 is normal operation with a rate-limited provider and says how
        // long to wait (CLAUDE.md gotcha #5). Show the wait, never auto-retry.
        const wait = err.retryAfter ? ` Try again in about ${err.retryAfter} s.` : ''
        setAnalyzeError(err.status === 429 ? `${err.message}${wait}` : err.message)
      } finally {
        setAnalyzing(false)
        onSettled?.()
      }
    },
    [caseId, apply, onSettled],
  )

  return { analysis, job, jobFailed, stalled, analyzing, analyzeError, analyze }
}

export default function CaseFlow({ caseId, stepId }) {
  const [manifest, setManifest] = useState(null)
  const [flow, setFlow] = useState(null)
  const [error, setError] = useState('')
  const ready = manifest?.status === 'ready'

  const reload = useCallback(async () => {
    try {
      const [m, f] = await Promise.all([getCase(caseId), getFlow(caseId)])
      setManifest(m)
      setFlow(f)
    } catch (err) {
      setError(err.message)
    }
  }, [caseId])

  // Asked again when the analyst opens another step and when they come back to
  // the tab - a decision taken on a finding's own page changes the steps.
  useEffect(() => {
    reload()
  }, [reload, stepId])
  useEffect(() => {
    window.addEventListener('focus', reload)
    return () => window.removeEventListener('focus', reload)
  }, [reload])

  // While the file is still being processed, follow it.
  const processing = manifest && !['ready', 'failed'].includes(manifest.status)
  useEffect(() => {
    if (!processing) return undefined
    const t = setInterval(reload, POLL_MS)
    return () => clearInterval(t)
  }, [processing, reload])

  // #/case/<id> with no step opens the one the server recommends. replace()
  // keeps the bare address out of the Back history.
  useEffect(() => {
    if (!stepId && flow?.recommended) window.location.replace(stepHref(caseId, flow.recommended))
  }, [stepId, flow, caseId])

  const ai = useAnalysis(caseId, ready, reload)
  const step = flow?.steps.find((s) => s.id === stepId)
  const [statusLabel] = statusOf(manifest?.status)

  return (
    <section className="page">
      <div className="top-bar">
        <div>
          {/* Where the case sits: customer, then project, both one click away. */}
          <div className="back-link">
            <a href="#/cases">Cases</a> ›{' '}
            {manifest?.company_id && (
              <>
                <a href={`#/customers/${manifest.company_id}`}>{manifest.company_name}</a> ›{' '}
                {manifest.project_id && (
                  <>
                    <a href={`#/customers/${manifest.company_id}/projects/${manifest.project_id}`}>
                      {manifest.project_name}
                    </a>{' '}
                    ›{' '}
                  </>
                )}
              </>
            )}
            {manifest ? manifest.original_filename : caseId}
          </div>
          <h1>
            {step ? step.title : 'Case'}
            <span className="muted"> · {manifest ? manifest.original_filename : caseId}</span>
          </h1>
          <div className="subtitle">
            {manifest && (
              <>
                <code>{manifest.case_id}</code> · uploaded {fmtTime(manifest.uploaded_at)} · status: {statusLabel}
                {manifest.note ? ` · ${manifest.note}` : ''}
              </>
            )}
          </div>
        </div>
      </div>

      {error && <div className="panel"><Empty>Could not load: {error}</Empty></div>}
      {!error && !flow && <div className="panel"><Empty>Loading...</Empty></div>}
      {flow && <StepBar caseId={caseId} flow={flow} current={stepId} />}

      {flow && step && (
        <div className="panel step-panel">
          <div className={`step-reason step-${step.state}`}>{step.reason}</div>
          <StepBody step={step} caseId={caseId} manifest={manifest} ready={ready} ai={ai} reload={reload} />
          <div className="step-standards">
            Standards:{' '}
            {step.standards.map((s, i) => (
              <span key={s.source + s.ref}>
                {i > 0 && ' · '}
                {s.source}
                {s.ref ? ` (${s.ref})` : ''}
              </span>
            ))}
          </div>
        </div>
      )}
      {flow && stepId && !step && (
        <div className="panel">
          <Empty>
            No step called &quot;{stepId}&quot;. <a href={stepHref(caseId, flow.recommended)}>Open the current step</a>.
          </Empty>
        </div>
      )}
    </section>
  )
}

function StepBody({ step, caseId, manifest, ready, ai, reload }) {
  const cite = (key) => {
    window.location.hash = `#/finding/${caseId}/${encodeURIComponent(key)}`
  }
  if (!manifest) return null
  if (step.id !== 'ingest' && !ready && manifest.status !== 'failed') {
    return <Empty>This step opens once the file has been processed (see Ingest).</Empty>
  }

  switch (step.id) {
    case 'ingest':
      return (
        <>
          {ready && (
            <div className="meta-line" style={{ marginTop: 0 }}>
              <SeverityPill severity={manifest.severity} /> · {fmtNum(manifest.flagged_count)} flagged of{' '}
              {fmtNum(manifest.total_rows)} events
            </div>
          )}
          {manifest.status === 'failed' && <Empty>Processing failed: {manifest.error || 'unknown cause'}</Empty>}
          {ready && <MappingNote manifest={manifest} />}
          <div className="section-label">Evidence and chain of custody</div>
          <Evidence caseId={caseId} />
          {ready && (
            <>
              <div className="section-label">Events</div>
              <EventsTable caseId={caseId} />
            </>
          )}
        </>
      )
    case 'triage':
      // Every finding of the case, the ones outside the status workflow too.
      return <ReviewPanel caseId={caseId} onChanged={reload} />
    case 'investigate':
      return (
        <>
          <TrackedFindings caseId={caseId} mode="investigate" />
          <GraphAndRisk caseId={caseId} />
          {ai.analysis?.timeline?.length > 0 && (
            <>
              <div className="section-label">Timeline written by the AI</div>
              <Timeline items={ai.analysis.timeline} onCite={cite} />
            </>
          )}
        </>
      )
    case 'respond':
      return <TrackedFindings caseId={caseId} mode="respond" />
    case 'analyse':
      return <AnalyseStep ai={ai} cite={cite} />
    case 'report':
      return <ReportStep caseId={caseId} manifest={manifest} />
    default:
      return null
  }
}

/** The high and critical findings of the case - the ones in the status
 *  workflow - each opening its own page, where they are assigned, investigated,
 *  contained and resolved. Respond adds the time to contain. */
function TrackedFindings({ caseId, mode }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let alive = true
    getFindings(caseId)
      .then((d) => alive && setData(d))
      .catch((err) => alive && setError(err.message))
    return () => {
      alive = false
    }
  }, [caseId])

  if (error) return <Empty>{error}</Empty>
  if (!data) return <Empty>Loading...</Empty>
  const rows = data.findings.filter((f) => f.lifecycle?.tracked)
  if (!rows.length) return <Empty>No high or critical findings - nothing enters the status workflow.</Empty>
  const lc = data.lifecycle_summary || {}
  return (
    <>
      {mode === 'respond' && (
        <div className="meta-line" style={{ marginTop: 0 }}>
          {Object.entries(lc.counts || {}).map(([k, v]) => `${k} ${v}`).join(' · ')}
          {' · '}mean time to contain:{' '}
          {lc.mttc_seconds != null
            ? `${(lc.mttc_seconds / 3600).toFixed(1)} h over ${lc.mttc_n} true positive${lc.mttc_n === 1 ? '' : 's'}`
            : 'no true positive contained yet'}
        </div>
      )}
      <div className="table-scroll">
        <table className="ov-table">
          <thead>
            <tr>
              <th>Finding</th>
              <th>Severity</th>
              <th>Description</th>
              <th>Review</th>
              <th>Status</th>
              <th>Assignee</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <tr key={f.key}>
                <td>
                  <a className="table-link mono" href={`#/finding/${caseId}/${encodeURIComponent(f.key)}`}>
                    {f.fd || f.rid}
                  </a>
                </td>
                <td><span className={`sev-tag sev-tag-${f.level}`}>{LEVEL_EN[f.level] || f.level}</span></td>
                <td>{f.descr}</td>
                <td>{f.review?.status}</td>
                <td>
                  {f.lifecycle.status}
                  {f.review?.status === 'Rejected' && f.lifecycle.status !== 'Resolved' && (
                    <div className="cell-sub">rejected - not closed</div>
                  )}
                </td>
                <td>{f.lifecycle.assignee || <span className="muted">unassigned</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

/** Attack graph and risk ranking, from the findings in SQL (GET /graph). */
function GraphAndRisk({ caseId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let alive = true
    getGraph(caseId)
      .then((d) => alive && setData(d))
      .catch((err) => alive && setError(err.message))
    return () => {
      alive = false
    }
  }, [caseId])

  if (error) return <Empty>{error}</Empty>
  if (!data) return null
  return (
    <>
      <div className="section-label">Attack graph</div>
      {data.graph?.edges?.length ? <AttackGraph graph={data.graph} /> : <Empty>No edges - no finding links two entities.</Empty>}
      <div className="section-label">Risk ranking</div>
      <RiskTables risk={data.risk || {}} />
    </>
  )
}

function AnalyseStep({ ai, cite }) {
  const { analysis, job, jobFailed, stalled, analyzing, analyzeError, analyze } = ai
  return (
    <>
      <div className="meta-line" style={{ marginTop: 0 }}>
        The narrative is written by an AI model from the computed findings. It is not evidence: every claim
        cites the findings it rests on.
      </div>
      {analyzing && <Empty style={{ paddingTop: 14 }}>Analysing with AI... (this can take up to a minute)</Empty>}
      {/* A queued job keeps any older analysis on screen below it - still valid,
          only possibly stale. */}
      {!analyzing && job && <AnalysisProgress job={job} stale={!!analysis} stalled={stalled} />}
      {!analyzing && jobFailed && <Empty style={{ paddingTop: 14 }}>Analysis failed: {jobFailed}</Empty>}
      {!analyzing && analyzeError && <Empty style={{ paddingTop: 14 }}>{analyzeError}</Empty>}
      <div className="lc-actions">
        <button className="secondary" disabled={analyzing || !!job} onClick={() => analyze(!!analysis)}>
          {job ? 'Analysing...' : analysis ? 'Re-analyse' : 'Analyse with AI'}
        </button>
      </div>
      {!analyzing && analysis && (
        <>
          <div className="ws-overview-summary" style={{ marginTop: 14 }}>{analysis.summary || ''}</div>
          {analysis.attack_chain?.length > 0 && (
            <>
              <div className="ws-overview-mini"><ChainFlow chain={analysis.attack_chain} /></div>
              <div className="section-label">Attack chain</div>
              <ChainStages chain={analysis.attack_chain} onCite={cite} />
            </>
          )}
          {analysis.timeline?.length > 0 && (
            <>
              <div className="section-label">Timeline</div>
              <Timeline items={analysis.timeline} onCite={cite} />
            </>
          )}
          {analysis.recommendations?.length > 0 && (
            <>
              <div className="section-label">Recommendations</div>
              <Recommendations items={analysis.recommendations} />
            </>
          )}
          <AnalysisMeta meta={analysis._meta} />
        </>
      )}
    </>
  )
}

function ReportStep({ caseId, manifest }) {
  const [data, setData] = useState(null)
  useEffect(() => {
    let alive = true
    getFindings(caseId)
      .then((d) => alive && setData(d))
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [caseId])
  const s = data?.review_summary || {}
  const unreviewed = s.Unreviewed || 0
  return (
    <>
      {data && (
        <div className={`rv-gate ${data.ready_for_report ? 'ok' : 'blocked'}`}>
          {data.ready_for_report ? (
            'Every finding is reviewed - the report gate is open.'
          ) : (
            <>
              {unreviewed} finding{unreviewed === 1 ? '' : 's'} not reviewed - a final report waits for them.{' '}
              <a href={stepHref(caseId, 'triage')}>Go to Triage</a>
            </>
          )}
        </div>
      )}
      <Veris caseId={caseId} />
      {manifest.flagged_count > 0 && (
        <div className="meta-line">
          {/* Same-origin link, so the session cookie goes with it. */}
          <a href={`/api/cases/${encodeURIComponent(caseId)}/attack-layer`} download>
            Download ATT&amp;CK Navigator layer
          </a>{' '}
          - this case&apos;s techniques, scored by severity, for the MITRE ATT&amp;CK Navigator
          <br />
          <a href={`/api/cases/${encodeURIComponent(caseId)}/stix`} download>
            Download STIX 2.1 bundle
          </a>{' '}
          - findings as sightings of ATT&amp;CK techniques, for a threat-intel platform or SIEM
        </div>
      )}
      <Empty style={{ paddingTop: 14 }}>The final written report is not built yet (IAI-72, IAI-73).</Empty>
    </>
  )
}
