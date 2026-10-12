import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { getAnalysis, getCase, runAnalysis } from '../api.js'
import { fmtNum, fmtTime, statusOf } from '../format.js'
import { Empty, SeverityPill } from '../components/common.jsx'
import Workspace from '../components/Workspace.jsx'
import EventsTable from '../components/EventsTable.jsx'
import ReviewPanel from '../components/ReviewPanel.jsx'
import AttackGraph from '../components/AttackGraph.jsx'
import MappingNote from '../components/Mapping.jsx'
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
    return { report: null, job: null, failed: body.summary || 'การวิเคราะห์ล้มเหลว' }
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

export default function Result({ caseId }) {
  const [manifest, setManifest] = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [job, setJob] = useState(null)
  const [jobFailed, setJobFailed] = useState('')
  const [stalled, setStalled] = useState(false)
  const [error, setError] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [analyzeError, setAnalyzeError] = useState('')
  const [tab, setTab] = useState(undefined)

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
        const wait = err.retryAfter ? ` รออีกประมาณ ${err.retryAfter} วินาที` : ''
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

    out.push({
      key: 'overview',
      label: 'Overview',
      node: (
        <>
          <div className="meta-line" style={{ marginTop: 0 }}>
            <SeverityPill severity={manifest.severity} /> · findings{' '}
            {fmtNum(manifest.flagged_count)} / {fmtNum(manifest.total_rows)} rows
          </div>
          <MappingNote manifest={manifest} />
          {analyzing && (
            <Empty style={{ paddingTop: 14 }}>กำลังวิเคราะห์ด้วย AI... (อาจใช้เวลาถึง 1 นาที)</Empty>
          )}
          {/* A queued job keeps any older analysis on screen below it - it is
              still valid evidence, only possibly stale. */}
          {!analyzing && job && (
            <AnalysisProgress job={job} stale={!!analysis} stalled={stalled} />
          )}
          {!analyzing && jobFailed && (
            <Empty style={{ paddingTop: 14 }}>วิเคราะห์ไม่สำเร็จ: {jobFailed}</Empty>
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
              <Empty style={{ paddingTop: 14 }}>ยังไม่ได้วิเคราะห์เคสนี้ด้วย AI</Empty>
              <button className="secondary" onClick={() => analyze(false)}>
                วิเคราะห์ด้วย AI
              </button>
            </>
          )}
        </>
      ),
    })

    out.push({
      key: 'events',
      label: 'Events',
      count: manifest.flagged_count,
      node: <EventsTable caseId={caseId} />,
    })

    out.push({ key: 'review', label: 'Review', node: <ReviewPanel caseId={caseId} /> })

    if (analysis) {
      out.push({
        key: 'chain',
        label: 'Attack Chain',
        count: (analysis.attack_chain || []).length,
        node: <ChainStages chain={analysis.attack_chain} />,
      })

      const edges = analysis.graph?.edges?.length || 0
      if (edges) {
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
      if (riskCount) {
        out.push({
          key: 'risk',
          label: 'Risk Ranking',
          count: riskCount,
          node: <RiskTables risk={risk} />,
        })
      }

      if (analysis.timeline?.length) {
        out.push({
          key: 'timeline',
          label: 'Timeline',
          count: analysis.timeline.length,
          node: <Timeline items={analysis.timeline} />,
        })
      }

      if (analysis.recommendations?.length) {
        out.push({
          key: 'recs',
          label: 'Recommendations',
          count: analysis.recommendations.length,
          node: <Recommendations items={analysis.recommendations} />,
        })
      }
    }

    return out
  }, [manifest, analysis, analyzing, analyzeError, job, jobFailed, stalled, caseId, analyze])

  const [statusLabel] = statusOf(manifest?.status)

  return (
    <section className="page">
      <div className="top-bar">
        <div>
          <a href="#/dashboard" className="back-link">
            &larr; กลับไป Overview
          </a>
          <h1>{manifest ? manifest.original_filename : caseId}</h1>
          <div className="subtitle">
            {manifest && (
              <>
                <code>{manifest.case_id}</code> · อัปโหลดเมื่อ {fmtTime(manifest.uploaded_at)} ·
                สถานะ: {statusLabel}
                {manifest.company_name ? ` · บริษัท: ${manifest.company_name}` : ''}
                {manifest.note ? ` · ${manifest.note}` : ''}
              </>
            )}
          </div>
        </div>
        {manifest?.status === 'ready' && (
          // A second job would only race the first for the same per-minute
          // token budget, and the server refuses it anyway (already_running).
          <button className="secondary" disabled={analyzing || !!job} onClick={() => analyze(true)}>
            {job ? 'กำลังวิเคราะห์...' : 'วิเคราะห์ใหม่'}
          </button>
        )}
      </div>

      <div className="panel">
        {error && <Empty>โหลดไม่สำเร็จ: {error}</Empty>}
        {!error && !manifest && <Empty>กำลังโหลด...</Empty>}
        {!error && manifest && manifest.status === 'failed' && (
          <Empty>เคสนี้ประมวลผลล้มเหลว: {manifest.error || 'ไม่ทราบสาเหตุ'}</Empty>
        )}
        {!error && manifest && !['ready', 'failed'].includes(manifest.status) && (
          <Empty>เคสนี้ยังไม่พร้อม รอการประมวลผลให้เสร็จก่อน</Empty>
        )}
        {!error && manifest?.status === 'ready' && tabs.length > 0 && (
          <Workspace tabs={tabs} activeKey={tab} onChange={setTab} />
        )}
      </div>
    </section>
  )
}
