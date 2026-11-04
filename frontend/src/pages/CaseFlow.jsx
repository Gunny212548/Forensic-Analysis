import { useCallback, useEffect, useState } from 'react'
import { getCase, getFindings, getFlow, getGraph, getIngest } from '../api.js'
import { useAccess } from '../permissions.js'
import { LEVEL_EN, fmtNum, fmtTime, shortTs, statusOf } from '../format.js'
import { Empty, SeverityPill } from '../components/common.jsx'
import { Badge, BigTotal, FactTiles, Section, SummaryCard, TotalRow } from '../components/cards.jsx'
import StepBar, { stepHref } from '../components/StepBar.jsx'
import EventsTable from '../components/EventsTable.jsx'
import ReviewPanel from '../components/ReviewPanel.jsx'
import AttackGraph from '../components/AttackGraph.jsx'
import AttackTimelineView from '../components/AttackTimelineView.jsx'
import MappingNote, { filesByLogSource } from '../components/Mapping.jsx'
import Evidence from '../components/Evidence.jsx'
import Question from '../components/Question.jsx'
import Reprocess, { Method } from '../components/Reprocess.jsx'
import { Detection, Lines, Periods, Sigma } from '../components/Period.jsx'
import Veris from '../components/Veris.jsx'
import DeleteCase from '../components/DeleteCase.jsx'
import ReportPanel from '../components/ReportPanel.jsx'
import { RiskTables } from '../components/analysis.jsx'

/** The case page: one case as six steps (docs/specs/case_flow_design.md), at
 *  #/case/<id>/<step>. It replaced the Reports / Attack Graph / Timeline pages,
 *  whose links redirect here (App.jsx). Each step shows the components those
 *  pages had, moved rather than rewritten; what a step's state is comes from
 *  the server (GET /flow), never from this page. */

// While a file is processed the page polls its manifest; 4s is cheap enough to leave running.
const POLL_MS = 4000

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
          {/* Said already once the case is ready (the user, 2026-10-27): Attack events'
              "N of M not decided yet" by the summary card's Analyst decided and the step
              box, Ingest's "events read, digest verified" by its Files read and custody. */}
          {!(ready && ['ingest', 'attack-events'].includes(step.id)) && (
            <div className={`step-reason step-${step.state}`}>{step.reason}</div>
          )}
          <StepBody step={step} caseId={caseId} manifest={manifest} ready={ready} reload={reload} />
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
  // While the AI is still explaining, its count here is the only progress on the page:
  // read again every 20 s, as the Attack events list does, until it is done.
  const aiRunning = ['queued', 'running'].includes(data?.ai_review?.status)
  useEffect(() => {
    if (!aiRunning) return undefined
    const t = setInterval(() => {
      getFindings(caseId).then(setData).catch(() => {})
    }, 20000)
    return () => clearInterval(t)
  }, [aiRunning, caseId])
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
      {data.sigma?.status === 'ran' && (
        <Section icon="settings" tone="muted" title="SigmaHQ rules" defaultOpen={false}
                 sub="The community rule set run beside ours, and what could not run on this evidence"
                 stats={[{ label: 'Ran', value: fmtNum(data.sigma.ran) }]}>
          <div className="ing-body"><Sigma sigma={data.sigma} /></div>
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

function StepBody({ step, caseId, manifest, ready, reload }) {
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
      // The step issues the report (the user, 2026-11-03): the draft first, the exports fold
      // underneath. The case's AI narrative left the page the same day (the user chose "A"): it
      // repeated the report's summary and the attack timeline, and read suggestions not decided;
      // the report's AI now drafts the recommendations too (docs/specs/forensic_report.md R-D10).
      return <ReportStep caseId={caseId} manifest={manifest} />
    default:
      return null
  }
}

/** The finding groups the analyst confirmed (accepted or modified), as an attack
 *  timeline (AttackTimelineView, shared with a project's). Story 6 adds the gaps
 *  between them, the assumptions written for each gap and the hypotheses. */
function AttackTimeline({ caseId }) {
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
  // Built once every suggestion is decided - one not decided is not proven
  // either way (the user, 2026-10-28), as on the Attack path step.
  if (data.findings.some((f) => (f.review?.status || 'Unreviewed') === 'Unreviewed')) {
    return (
      <Empty>
        Decide the remaining suggestions in <a href={stepHref(caseId, 'attack-events')}>Attack events</a> first.
      </Empty>
    )
  }
  // ts_first is the zone-stamped "YYYY-MM-DD HH:MM:SS+07:00" text, so it sorts
  // as written; a group whose time did not parse goes last.
  const rows = data.findings
    .filter((f) => ['Accepted', 'Modified'].includes(f.review?.status))
    .sort((a, b) => (a.ts_first || '\uffff').localeCompare(b.ts_first || '\uffff') || a.key.localeCompare(b.key))
  if (!rows.length) {
    return (
      <Empty>
        No attack event was confirmed - every suggestion was rejected.
      </Empty>
    )
  }
  return (
    <AttackTimelineView rows={rows} tacticOrder={data.tactic_order}
                        findingHref={(f) => `#/finding/${caseId}/${encodeURIComponent(f.key)}`} />
  )
}

/** Attack graph and risk ranking of the confirmed groups, in SQL (GET /graph) -
 *  nothing until every suggestion is decided (the user, 2026-10-28). */
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
  if (data.undecided) {
    return (
      <Empty>
        Decide the remaining suggestions in <a href={stepHref(caseId, 'attack-events')}>Attack events</a> first.
      </Empty>
    )
  }
  return (
    <>
      <div className="section-label">Attack graph</div>
      {data.graph?.edges?.length ? (
        <AttackGraph graph={data.graph} />
      ) : (
        <Empty>No edges - no confirmed attack event links two entities.</Empty>
      )}
      <div className="section-label">Risk ranking</div>
      <RiskTables risk={data.risk || {}} />
    </>
  )
}

/** The Report step issues the report (the user, 2026-11-03). One report per investigation
 *  (docs/specs/forensic_report.md R-D1), so the draft made here is the project's, from every case
 *  in it - the same one the project page shows. Its gate (every suggestion of every case
 *  decided, the question written) is ReportPanel's; the case's exports fold below it. */
function ReportStep({ caseId, manifest }) {
  return (
    <>
      {manifest.project_id ? (
        <ReportPanel
          project={{ company_id: manifest.company_id, project_id: manifest.project_id, name: manifest.project_name }}
          fromCase
        />
      ) : (
        <Empty style={{ paddingTop: 14 }}>
          A report is made for a project, from every case in it - move this case into one (Customers) first.
        </Empty>
      )}
      <Section icon="threat-intel" title="Exports of this case" defaultOpen={false}
               sub="VERIS classification, ATT&CK Navigator layer, STIX 2.1 bundle">
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
      </Section>
    </>
  )
}
