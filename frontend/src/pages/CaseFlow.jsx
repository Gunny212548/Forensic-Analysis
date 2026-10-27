import { useCallback, useEffect, useRef, useState } from 'react'
import { getAnalysis, getCase, getFindings, getFlow, getGraph, getIngest, runAnalysis } from '../api.js'
import { useAccess } from '../permissions.js'
import { LEVEL_EN, fmtNum, fmtTime, shortTs, statusOf } from '../format.js'
import { Empty, SeverityPill } from '../components/common.jsx'
import { Badge, BigTotal, FactTiles, Section, SummaryCard, TotalRow } from '../components/cards.jsx'
import StepBar, { stepHref } from '../components/StepBar.jsx'
import EventsTable from '../components/EventsTable.jsx'
import ReviewPanel from '../components/ReviewPanel.jsx'
import AttackGraph from '../components/AttackGraph.jsx'
import MappingNote, { filesByLogSource } from '../components/Mapping.jsx'
import Evidence from '../components/Evidence.jsx'
import Question from '../components/Question.jsx'
import Reprocess, { Method } from '../components/Reprocess.jsx'
import { Detection, Lines, Periods } from '../components/Period.jsx'
import Veris from '../components/Veris.jsx'
import DeleteCase from '../components/DeleteCase.jsx'
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
    <section className="page case-page">
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
        <DeleteCase manifest={manifest} />
      </div>

      {error && <div className="panel"><Empty>Could not load: {error}</Empty></div>}
      {!error && !flow && <div className="panel"><Empty>Loading...</Empty></div>}
      {ready && flow && <CaseSummary caseId={caseId} manifest={manifest} flow={flow} />}
      {flow && <StepBar caseId={caseId} flow={flow} current={stepId} />}

      {flow && step && (
        <div className="panel step-panel">
          {/* Attack events' reason is "N of M not decided yet" - the summary card's
              Analyst decided and the step box say it already (the user, 2026-10-27). */}
          {step.id !== 'attack-events' && <div className={`step-reason step-${step.state}`}>{step.reason}</div>}
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

const LEVELS = ['critical', 'high', 'medium', 'low', 'informational']
const LEVEL_TONE = { critical: 'danger', high: 'warn', medium: 'info' }

/** The case at a glance, above its steps (the SOCRadar layout, 2026-10-27):
 *  what was uploaded and how much it holds, the suggestions by the day their
 *  first event happened, and on the right how many there are and how far the
 *  AI and the analyst are through them. Read again with the step bar (`flow`
 *  changes on every reload), so a decision taken below shows here. */
function CaseSummary({ caseId, manifest, flow }) {
  const [data, setData] = useState(null)
  useEffect(() => {
    let alive = true
    getFindings(caseId)
      .then((d) => alive && setData(d))
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [caseId, flow])
  if (!data) return null

  const fs = data.findings || []
  const top = LEVELS.find((l) => fs.some((f) => f.level === l))
  const tone = LEVEL_TONE[top] || (fs.length ? 'muted' : 'ok')
  const byLevel = LEVELS.filter((l) => l !== 'informational')
    .map((l) => [l, fs.filter((f) => f.level === l).length])
    .filter(([, n]) => n)
  const explained = fs.filter((f) => f.ai_review?.what_happened).length
  const undecided = data.review_summary?.Unreviewed || 0
  const areasHit = new Set(fs.map((f) => f.area).filter(Boolean)).size
  const files = manifest.members?.length || 1
  return (
    <SummaryCard
      label="Case summary"
      side={
        <BigTotal
          icon="shield-alert"
          tone={tone}
          label="Suggestions"
          value={fmtNum(fs.length)}
          badge={
            fs.length ? (
              <Badge tone={tone}>{byLevel.map(([l, n]) => `${n} ${l}`).join(' · ')}</Badge>
            ) : (
              <Badge tone="ok">Nothing suggested</Badge>
            )
          }
        >
          <TotalRow label="AI explained">{fmtNum(explained)} / {fmtNum(fs.length)}</TotalRow>
          <TotalRow label="Analyst decided">{fmtNum(fs.length - undecided)} / {fmtNum(fs.length)}</TotalRow>
          <TotalRow label="Flagged events">{fmtNum(manifest.flagged_count)}</TotalRow>
        </BigTotal>
      }
    >
      <FactTiles
        facts={[
          { label: 'Uploaded', value: <span className="mono">{shortTs(fmtTime(manifest.uploaded_at))}</span>,
            title: fmtTime(manifest.uploaded_at) },
          { label: 'Highest severity', value: <SeverityPill severity={manifest.severity} /> },
          { label: 'Areas', value: <><strong>{areasHit}</strong> of {(data.areas || []).length} areas</> },
          { label: 'Evidence',
            value: <><strong>{fmtNum(files)}</strong> {files === 1 ? 'file' : 'files'} · <strong>{fmtNum(manifest.total_rows)}</strong> events</> },
        ]}
      />
      <FirstSeen findings={fs} />
    </SummaryCard>
  )
}

/** Suggestions by the day their first event happened, as an area under a line
 *  - a count anyone can check against the list, nothing estimated. Plain SVG
 *  (nothing fetched). A day with no suggestion is 0, so a quiet stretch shows. */
function FirstSeen({ findings }) {
  const counts = {}
  for (const f of findings) {
    const d = (f.ts_first || '').slice(0, 10)
    if (/^\d{4}-\d{2}-\d{2}$/.test(d)) counts[d] = (counts[d] || 0) + 1
  }
  const known = Object.keys(counts).sort()
  if (!known.length) return null
  const days = []
  for (let t = Date.parse(`${known[0]}T00:00:00Z`); t <= Date.parse(`${known[known.length - 1]}T00:00:00Z`); t += 86400e3) {
    days.push(new Date(t).toISOString().slice(0, 10))
  }
  const W = 900
  const H = 110
  const v = days.map((d) => counts[d] || 0)
  const peak = Math.max(...v)
  const x = (i) => (days.length === 1 ? W / 2 : (i * W) / (days.length - 1))
  const line = v.map((n, i) => `${x(i).toFixed(1)},${(H - 4 - (n / peak) * (H - 12)).toFixed(1)}`).join(' ')
  const at = v.indexOf(peak)
  return (
    <div>
      <div className="ui-kicker">Suggestions by the day their first event happened</div>
      <div className="ui-headline">
        <strong>{fmtNum(findings.length)}</strong>
        from {days[0]} to {days[days.length - 1]} · most on {days[at]} ({peak})
      </div>
      <svg className="case-firstseen" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img"
           aria-label={`Suggestions per day of first event, most on ${days[at]} with ${peak}`}>
        <polygon points={`${x(0)},${H} ${line} ${x(days.length - 1)},${H}`} />
        <polyline points={line} />
      </svg>
      <div className="case-firstseen-axis mono">
        <span>{days[0]}</span>
        {days.length > 2 && <span>{days[Math.floor(days.length / 2)]}</span>}
        {days.length > 1 && <span>{days[days.length - 1]}</span>}
      </div>
    </div>
  )
}

/** Story 3: the investigation's question, the warnings and the
 *  reproducibility record with the Re-process button, around the custody block
 *  (children). Reloaded when the case's status changes, so a re-process that
 *  finishes shows its new record. */
function IngestRecord({ caseId, status, reload, children }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  // Bumped on every save - and the status is in the key too - so the custody
  // block (children) remounts and shows the new custody lines.
  const [version, setVersion] = useState(0)
  const load = useCallback(async () => {
    try {
      setData(await getIngest(caseId))
      setError('')
    } catch (err) {
      setError(err.message)
    }
  }, [caseId])
  useEffect(() => {
    load()
  }, [load, status])

  const saved = useCallback(() => {
    load()
    reload()
    setVersion((v) => v + 1)
  }, [load, reload])

  if (error) return <Empty>{error}</Empty>
  if (!data) return <Empty>Loading...</Empty>
  // The reference tables fold away with their size in the head (the user,
  // 2026-10-27: too much on Ingest); warnings and what needs the analyst stay open.
  const periods = data.periods || []
  const firsts = periods.map((p) => p.first).filter(Boolean).sort()
  const lasts = periods.map((p) => p.last).filter(Boolean).sort()
  const lineRules = Object.keys(data.lines || {})
  return (
    <>
      {data.warnings.length > 0 && (
        <div className="map-note map-warn">
          {data.warnings.map((w) => (
            <div key={w}>{w}</div>
          ))}
        </div>
      )}
      <Section icon="findings" tone="info" title="Question" sub="What this investigation asks - kept on the project">
        <div className="ing-body">
          <Question caseId={caseId} investigation={data.investigation} onSaved={saved} />
        </div>
      </Section>
      <Section icon="shield-alert" tone="ok" title="Evidence and chain of custody"
               sub="The file's digest, checked before every run, and every action on it">
        <div className="ing-body" key={`${version}-${status}`}>{children}</div>
      </Section>
      <Section icon="clock" tone="muted" title="Period each file covers" defaultOpen={false}
               sub="First and last event, gaps and events per day, file by file"
               stats={[
                 { label: 'Files', value: fmtNum(periods.length) },
                 { label: 'From', value: firsts[0]?.slice(0, 10) || '—' },
                 { label: 'To', value: lasts[lasts.length - 1]?.slice(0, 10) || '—' },
               ]}>
        <div className="ing-body"><Periods periods={data.periods} /></div>
      </Section>
      {data.detection && (
        <Section icon="dashboard" tone="muted" title="Rules per product and area" defaultOpen={false}
                 sub="Which rules ran on each product's rows, area by area, or why none applies"
                 stats={[{ label: 'Products', value: fmtNum(data.detection.length) }]}>
          <div className="ing-body"><Detection detection={data.detection} /></div>
        </Section>
      )}
      {lineRules.length > 0 && (
        <Section icon="settings" tone="muted" title="How each line was drawn" defaultOpen={false}
                 sub="Where each threshold rule took its line from on this evidence"
                 stats={[{ label: 'Rules', value: fmtNum(lineRules.length) }]}>
          <div className="ing-body"><Lines lines={data.lines} /></div>
        </Section>
      )}
      <Section icon="upload" tone="muted" title="Method of the last run"
               sub="Versions and settings, to run it again the same way">
        <div className="ing-body">
          <Method method={data.method} />
          <Reprocess caseId={caseId} ingest={data} onReprocessed={saved} />
        </div>
      </Section>
    </>
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
    case 'ingest': {
      const files = manifest.members?.length || 1
      const sources = ready ? filesByLogSource(manifest) : []
      return (
        <div className="ing-sections">
          {manifest.status === 'failed' && <Empty>Processing failed: {manifest.error || 'unknown cause'}</Empty>}
          {ready && (
            <Section icon="cases" tone="info" title="Files read"
                     sub={sources.map(([name, n]) => `${name} ${fmtNum(n)}`).join(' · ')}
                     stats={[
                       { label: 'Files', value: fmtNum(files) },
                       { label: 'Events', value: fmtNum(manifest.total_rows) },
                       { label: 'Flagged', value: fmtNum(manifest.flagged_count) },
                     ]}
                     pill={<SeverityPill severity={manifest.severity} />}>
              <div className="ing-body"><MappingNote manifest={manifest} /></div>
            </Section>
          )}
          <IngestRecord caseId={caseId} status={manifest.status} reload={reload}>
            <Evidence caseId={caseId} />
          </IngestRecord>
          {ready && (
            <Section icon="dashboard" tone="muted" title="Events, in file order" defaultOpen={false} lazy
                     sub="Every event as it stands in the files"
                     stats={[{ label: 'Events', value: fmtNum(manifest.total_rows) }]}>
              <div className="ing-body"><EventsTable caseId={caseId} /></div>
            </Section>
          )}
        </div>
      )
    }
    case 'timeline':
      // Every event by its time. One evidence item for now; across the
      // project's files, with pivots and silent periods, in story 4.
      return <EventsTable caseId={caseId} order="time" />
    case 'attack-events':
      // The rules suggest, the analyst confirms or rejects each finding group.
      return <ReviewPanel caseId={caseId} onChanged={reload} />
    case 'attack-timeline':
      return <AttackTimeline caseId={caseId} />
    case 'attack-path':
      return <GraphAndRisk caseId={caseId} />
    case 'report':
      return (
        <>
          <ReportStep caseId={caseId} manifest={manifest} />
          <div className="section-label">Narrative drafted by the AI</div>
          <AnalyseStep ai={ai} cite={cite} />
        </>
      )
    default:
      return null
  }
}

/** The finding groups the analyst confirmed (accepted or modified): the
 *  ATT&CK tactics they reach as a row of stages, in ATT&CK's order - only the
 *  tactics found, the user's choice of 2026-10-22 - and below, every group in
 *  the order its first event happened. A stage filters the list. Story 6 adds
 *  the gaps between them, the assumptions written for each gap and the
 *  hypotheses. */
function AttackTimeline({ caseId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [stage, setStage] = useState('')
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
  // ts_first is the zone-stamped "YYYY-MM-DD HH:MM:SS+07:00" text, so it sorts
  // as written; a group whose time did not parse goes last.
  const rows = data.findings
    .filter((f) => ['Accepted', 'Modified'].includes(f.review?.status))
    .sort((a, b) => (a.ts_first || '￿').localeCompare(b.ts_first || '￿') || a.key.localeCompare(b.key))
  if (!rows.length) {
    return (
      <Empty>
        No attack event confirmed yet. <a href={stepHref(caseId, 'attack-events')}>Decide them in Attack events</a>.
      </Empty>
    )
  }
  const names = Object.fromEntries((data.tactic_order || []).map((t) => [t.id, t.name]))
  const stagesOf = (f) => (f.tactics?.length ? f.tactics : ['unmapped'])
  // The stages reached, in ATT&CK's order, then the groups no technique maps.
  const stages = [...(data.tactic_order || []).map((t) => t.id), 'unmapped']
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
              <th>ATT&amp;CK</th>
              <th>Events</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((f) => (
              <tr key={f.key}>
                <td className="mono">{f.ts_first || ''}</td>
                <td className="mono">{f.ts_last && f.ts_last !== f.ts_first ? f.ts_last : ''}</td>
                <td>{stagesOf(f).map((t) => names[t] || 'Not mapped').join(', ')}</td>
                <td>
                  <a className="table-link" href={`#/finding/${caseId}/${encodeURIComponent(f.key)}`}>
                    {f.descr}
                  </a>
                  <div className="cell-sub">
                    {f.fd || f.rid} · {LEVEL_EN[f.level] || f.level}
                  </div>
                </td>
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
  const { can, why } = useAccess() // an analyst's or a manager's (IAI-14)
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
        <button
          className="secondary"
          disabled={analyzing || !!job || !can('case:analyze')}
          title={why('case:analyze')}
          onClick={() => analyze(!!analysis)}
        >
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
            'Every suggestion is decided - the report gate is open.'
          ) : (
            <>
              {unreviewed} suggestion{unreviewed === 1 ? '' : 's'} not decided - a final report waits for them.{' '}
              <a href={stepHref(caseId, 'attack-events')}>Go to Attack events</a>
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
