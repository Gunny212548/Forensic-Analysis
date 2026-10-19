import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { getAnalysis, getCase, runAnalysis } from '../api.js'
import { fmtNum, fmtTime, statusOf } from '../format.js'
import { Empty, SeverityPill } from '../components/common.jsx'
import Workspace from '../components/Workspace.jsx'
import EventsTable from '../components/EventsTable.jsx'
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

// A queued map-reduce job runs for minutes (about one model call a minute),
// so the page polls rather than holding one request open. Nothing here is
// real-time: 4s is often enough to see a batch tick over and cheap enough to
// leave running while an analyst reads the old report.
const POLL_MS = 4000

// The server stops reporting a job that has not written progress for 15
// minutes (it treats it as gone), and answers the poll with the older analysis
// or a 404 instead. Observed live: a map call can outlast that window, and the
// job then reappears. So an empty poll is not the end of the job - but after a
// minute of them the progress numbers on screen are no longer being confirmed
// by anything, and the panel says so rather than freezing silently.
const STALL_POLLS = 15

/** Split any /analyze or /analysis body into the three things the page
 *  renders: a finished report, a running job, a failure reason.
 *
 *  Both in-progress answers are 2xx, so the HTTP code says nothing - the body
 *  does. When a job is running the server returns either the OLD finished
 *  analysis (fully renderable, just stale) or a stub whose arrays are empty
 *  and whose `summary` is a progress sentence. `_meta` is written by the
 *  analysis pipeline and never by the job view, so it is what tells the two
 *  apart; rendering the stub as a report is exactly the bug this avoids.
 */
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

/** The case-level pages that replaced #/result: Reports (summary, chain,
 *  recommendations, events, evidence), Attack Graph (graph and risk ranking) and
 *  Timeline. One component so the AI analysis - its polling, its progress, its
 *  failures - is handled in one place; `view` picks what is shown. A single
 *  finding (review, workflow, source events) is #/finding/<case>/<key>. */
export const VIEWS = {
  reports: { title: 'Reports', route: 'reports' },
  'attack-graph': { title: 'Attack Graph', route: 'attack-graph' },
  timeline: { title: 'Timeline', route: 'timeline' },
}

export default function CaseView({ caseId, view = 'reports' }) {
  const [manifest, setManifest] = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [job, setJob] = useState(null)
  const [jobFailed, setJobFailed] = useState('')
  const [stalled, setStalled] = useState(false)
  const [error, setError] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [analyzeError, setAnalyzeError] = useState('')
  const [tab, setTab] = useState(undefined)
  // A citation chip in the chain/timeline opens its finding's page.
  const cite = useCallback((key) => {
    window.location.hash = `#/finding/${caseId}/${encodeURIComponent(key)}`
  }, [caseId])

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
    let alive = true
    ;(async () => {
      try {
        const m = await getCase(caseId)
        if (!alive) return
        setManifest(m)
        if (m.status === 'ready') {
          const a = await getAnalysis(caseId)
          if (alive) apply(a)
        }
      } catch (err) {
        if (alive) setError(err.message)
      }
    })()
    return () => {
      alive = false
    }
  }, [caseId, apply])

  // Polls only while a job is in flight. The interval is torn down by this
  // effect's cleanup: on unmount (leaving the page), on opening another case
  // (App.jsx keys Result by case id, so that is a remount), and as soon as a
  // poll comes back "ready"/"failed", which clears `job` and re-runs this.
  // Depends on the boolean, not the job object, so a progress update does not
  // restart the timer.
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
      // A poll that answers nothing (404, or a dropped connection while the
      // server is busy) is not news: keep the last state on screen.
      if (body) {
        emptyPolls.current = 0
        setStalled(false)
        apply(body)
      } else {
        emptyPolls.current += 1
        if (emptyPolls.current >= STALL_POLLS) setStalled(true)
      }
    }, POLL_MS)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [polling, caseId, apply])

  const analyze = useCallback(
    async (force) => {
      setAnalyzing(true)
      setAnalyzeError('')
      setJobFailed('')
      setTab('overview')
      try {
        // 200 = the narrative (small case, unchanged). 202 = a map-reduce job
        // was queued instead; the polling effect above takes it from here.
        apply(await runAnalysis(caseId, force))
      } catch (err) {
        // 429 is normal operation here: the model allows about one analysis a
        // minute and says how long to wait (CLAUDE.md gotcha #5). Show the
        // wait rather than a generic failure, and never auto-retry.
        const wait = err.retryAfter ? ` Try again in about ${err.retryAfter} s.` : ''
        setAnalyzeError(err.status === 429 ? `${err.message}${wait}` : err.message)
      } finally {
        setAnalyzing(false)
      }
    },
    [caseId, apply],
  )

  const tabs = useMemo(() => {
    if (!manifest || manifest.status !== 'ready') return []
    const out = []
    const needAnalysis = (label) => (
      <Empty>
        {label} comes from the AI analysis, which this case does not have yet.{' '}
        <a href={`#/reports/${caseId}`}>Run it from Reports</a>.
      </Empty>
    )

    if (view === 'reports') out.push({
      key: 'overview',
      label: 'Overview',
      node: (
        <>
          <div className="meta-line" style={{ marginTop: 0 }}>
            <SeverityPill severity={manifest.severity} /> · {fmtNum(manifest.flagged_count)} flagged of{' '}
            {fmtNum(manifest.total_rows)} events
          </div>
          <MappingNote manifest={manifest} />
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
          {analyzing && (
            <Empty style={{ paddingTop: 14 }}>Analysing with AI... (this can take up to a minute)</Empty>
          )}
          {/* A queued job keeps any older analysis on screen below it - it is
              still valid evidence, only possibly stale. */}
          {!analyzing && job && (
            <AnalysisProgress job={job} stale={!!analysis} stalled={stalled} />
          )}
          {!analyzing && jobFailed && (
            <Empty style={{ paddingTop: 14 }}>Analysis failed: {jobFailed}</Empty>
          )}
          {!analyzing && analyzeError && <Empty style={{ paddingTop: 14 }}>{analyzeError}</Empty>}
          {!analyzing && analysis && (
            <>
              <div className="ws-overview-summary" style={{ marginTop: 14 }}>
                {analysis.summary || ''}
              </div>
              {analysis.attack_chain?.length > 0 && (
                <div className="ws-overview-mini">
                  <ChainFlow chain={analysis.attack_chain} />
                </div>
              )}
              <AnalysisMeta meta={analysis._meta} />
            </>
          )}
          {!analyzing && !analysis && !job && !jobFailed && (
            <>
              <Empty style={{ paddingTop: 14 }}>This case has not been analysed with AI yet.</Empty>
              <button className="secondary" onClick={() => analyze(false)}>
                Analyse with AI
              </button>
            </>
          )}
        </>
      ),
    })

    if (view === 'reports') {
      out.push({
        key: 'events',
        label: 'Events',
        count: manifest.flagged_count,
        node: <EventsTable caseId={caseId} />,
      })
      out.push({ key: 'evidence', label: 'Evidence', node: <Evidence caseId={caseId} /> })
    }

    if (analysis) {
      if (view === 'reports') out.push({
        key: 'chain',
        label: 'Attack Chain',
        count: (analysis.attack_chain || []).length,
        node: <ChainStages chain={analysis.attack_chain} onCite={cite} />,
      })

      const edges = analysis.graph?.edges?.length || 0
      if (view === 'attack-graph' && edges) {
        out.push({
          key: 'graph',
          label: 'Attack Graph',
          count: edges,
          node: <AttackGraph graph={analysis.graph} />,
        })
      }

      const risk = analysis.risk || {}
      const riskCount =
        (risk.sources || []).length +
        (risk.destinations || []).length +
        (risk.accounts || []).length
      if (view === 'attack-graph' && riskCount) {
        out.push({
          key: 'risk',
          label: 'Risk Ranking',
          count: riskCount,
          node: <RiskTables risk={risk} />,
        })
      }

      if (view === 'timeline' && analysis.timeline?.length) {
        out.push({
          key: 'timeline',
          label: 'Timeline',
          count: analysis.timeline.length,
          node: <Timeline items={analysis.timeline} onCite={cite} />,
        })
      }

      if (view === 'reports' && analysis.recommendations?.length) {
        out.push({
          key: 'recs',
          label: 'Recommendations',
          count: analysis.recommendations.length,
          node: <Recommendations items={analysis.recommendations} />,
        })
      }
    }

    if (view !== 'reports' && !out.length) {
      out.push({
        key: view,
        label: VIEWS[view].title,
        node: analysis
          ? <Empty>This analysis has no {VIEWS[view].title.toLowerCase()} data.</Empty>
          : job
            ? <AnalysisProgress job={job} stale={false} stalled={stalled} />
            : needAnalysis(VIEWS[view].title),
      })
    }

    return out
  }, [manifest, analysis, analyzing, analyzeError, job, jobFailed, stalled, caseId, analyze, cite, view])

  const [statusLabel] = statusOf(manifest?.status)

  return (
    <section className="page">
      <div className="top-bar">
        <div>
          {/* Where the case sits: customer, then project, both one click away. */}
          <div className="back-link">
            {manifest?.company_id ? (
              <>
                <a href="#/customers">Customers</a> ›{' '}
                <a href={`#/customers/${manifest.company_id}`}>{manifest.company_name}</a> ›{' '}
                {manifest.project_id && (
                  <>
                    <a href={`#/customers/${manifest.company_id}/projects/${manifest.project_id}`}>
                      {manifest.project_name}
                    </a>{' '}
                    ›{' '}
                  </>
                )}
                {manifest.original_filename}
              </>
            ) : (
              <a href="#/dashboard">&larr; Back to Overview</a>
            )}
          </div>
          <h1>
            {VIEWS[view].title}
            <span className="muted"> · {manifest ? manifest.original_filename : caseId}</span>
          </h1>
          <div className="subtitle">
            {manifest && (
              <>
                <code>{manifest.case_id}</code> · uploaded {fmtTime(manifest.uploaded_at)} ·
                status: {statusLabel}
                {manifest.note ? ` · ${manifest.note}` : ''}
              </>
            )}
          </div>
        </div>
        {manifest?.status === 'ready' && view === 'reports' && (
          // A second job would only race the first for the same per-minute
          // token budget, and the server refuses it anyway (already_running).
          <button className="secondary" disabled={analyzing || !!job} onClick={() => analyze(true)}>
            {job ? 'Analysing...' : 'Re-analyse'}
          </button>
        )}
      </div>

      <div className="panel">
        {error && <Empty>Could not load: {error}</Empty>}
        {!error && !manifest && <Empty>Loading...</Empty>}
        {!error && manifest && manifest.status === 'failed' && (
          <Empty>Processing this case failed: {manifest.error || 'unknown cause'}</Empty>
        )}
        {!error && manifest && !['ready', 'failed'].includes(manifest.status) && (
          <Empty>This case is not ready yet - wait for processing to finish.</Empty>
        )}
        {!error && manifest?.status === 'ready' && tabs.length > 0 && (
          <Workspace tabs={tabs} activeKey={tab} onChange={setTab} />
        )}
      </div>
    </section>
  )
}
