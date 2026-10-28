import { useEffect, useState } from 'react'
import {
  changeProject, deleteProject, getOverview, getProjectDeletion, getProjectGraph, getProjectTimeline, listCases,
  listCompanies, listProjects, moveCase, renameProject,
} from '../api.js'
import AttackGraph from '../components/AttackGraph.jsx'
import AttackTimelineView from '../components/AttackTimelineView.jsx'
import { RiskTables } from '../components/analysis.jsx'
import { ago, fmtNum, fmtTime, severityBucket } from '../format.js'
import { SeverityPill, StatusBadge } from '../components/common.jsx'
import { Badge, Section } from '../components/cards.jsx'
import { useAccess } from '../permissions.js'

const SEVS = ['critical', 'high', 'medium', 'low']
const SEV_EN = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }

/** One customer's profile, opened from the Customers list: who they are,
 *  since when, what they sent, their projects and every case - or, with
 *  `projectId`, one of those projects - an investigation, Open or Closed
 *  (specs/projects.md P1), which a manager closes and reopens here. */
export default function CustomerDetail({ companyId, projectId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [version, setVersion] = useState(0) // bumped to read everything again after a change

  useEffect(() => {
    let alive = true
    Promise.all([listCompanies(), getOverview(companyId), listCases(companyId), listProjects(companyId)])
      .then(([companies, overview, cases, projects]) => {
        if (!alive) return
        const customer = companies.find((c) => c.company_id === companyId)
        if (!customer) setError('Customer not found')
        else setData({ customer, overview, cases, projects })
      })
      .catch((err) => alive && setError(err.message))
    return () => {
      alive = false
    }
  }, [companyId, version])

  if (error) return <div className="panel empty">Could not load the customer: {error}</div>
  if (!data) return <div className="empty">Loading...</div>

  if (projectId) {
    const project = data.projects.find((p) => p.project_id === projectId)
    if (!project) return <div className="panel empty">Could not load the project: Project not found</div>
    return (
      <ProjectView
        customer={data.customer}
        project={project}
        cases={data.cases.filter((m) => m.project_id === projectId)}
        onChange={() => setVersion((v) => v + 1)}
      />
    )
  }

  const { customer, overview, cases, projects } = data
  const t = overview.totals
  const ready = cases.filter((m) => m.status === 'ready')
  const analysed = ready.filter((m) => m.has_analysis).length
  const lastActivity = overview.recent[0]?.ts || cases[0]?.uploaded_at || customer.created_at
  const highest = SEVS.find((s) => overview.case_severity[s] > 0)
  const uploaders = [...new Set(cases.map((m) => m.evidence?.recorded_by).filter(Boolean))]
  const sources = logSources(cases)
  const flagged = t.findings_critical + t.findings_high + t.findings_medium + t.findings_low

  return (
    <section className="page ov">
      <div className="back-link">
        <a href="#/customers">Customers</a> › {customer.name}
      </div>

      <div className="panel cp-head">
        <div className="cp-avatar" aria-hidden="true">
          {initials(customer.name)}
        </div>
        <div className="cp-title">
          <h1>{customer.name}</h1>
          <div className="subtitle">
            Customer since {fmtTime(customer.created_at).slice(0, 10)} · last activity {ago(lastActivity)}
          </div>
        </div>
        <a className="btn-secondary" href={`#/dashboard/${companyId}`}>
          Open dashboard
        </a>
      </div>

      <div className="cp-grid">
        <div className="panel">
          <h2>Profile</h2>
          <dl className="cp-dl">
            <dt>Customer ID</dt>
            <dd className="mono">{customer.company_id}</dd>
            <dt>Onboarded</dt>
            <dd>{fmtTime(customer.created_at)}</dd>
            <dt>Uploaded by</dt>
            <dd>{uploaders.length ? uploaders.map((u) => <div key={u}>{u}</div>) : '—'}</dd>
          </dl>
        </div>

        <div className="cp-main">
          <div className="panel">
            <h2>At a glance</h2>
            <dl className="cp-dl cp-glance">
              <dt>Cases</dt>
              <dd>
                {t.cases} <span className="cell-sub">{t.ready} ready · {t.processing} processing · {t.failed} failed</span>
              </dd>
              <dt>Projects</dt>
              <dd>{projects.length}</dd>
              <dt>Findings</dt>
              <dd>
                {fmtNum(t.reviewable)} <span className="cell-sub">{fmtNum(t.unreviewed)} awaiting review</span>
              </dd>
              <dt>Flagged events</dt>
              <dd>{fmtNum(flagged)}</dd>
              <dt>Highest severity</dt>
              <dd>{highest ? <span className={`sev-tag sev-tag-${highest}`}>{SEV_EN[highest]}</span> : '—'}</dd>
              {/* No report feature exists yet (IAI-55); the AI narrative per
                  case is the nearest thing, and is named as such. */}
              <dt>AI analyses</dt>
              <dd>
                {analysed} <span className="cell-sub">of {ready.length} ready cases</span>
              </dd>
              {/* Here, not in the Profile column: the names are long
                  (logsources.py) and read badly wrapped into a narrow one. */}
              <dt>Log sources</dt>
              <dd>
                {sources.length ? (
                  <ul className="cp-list">
                    {sources.map((s) => (
                      <li key={s}>{s}</li>
                    ))}
                  </ul>
                ) : (
                  'None identified yet'
                )}
              </dd>
            </dl>
          </div>

          <ProjectsPanel companyId={companyId} projects={projects} cases={cases} />

          <CasesPanel cases={cases} showProject projects={projects} companyId={companyId}
                      onChange={() => setVersion((v) => v + 1)} />
        </div>
      </div>
    </section>
  )
}

/** One investigation of the customer and the cases uploaded for it. */
function ProjectView({ customer, project, cases, onChange }) {
  const ready = cases.filter((m) => m.status === 'ready')
  const highest = highestOf(cases)
  const flagged = ready.reduce((n, m) => n + (m.flagged_count || 0), 0)
  const last = cases[0]?.uploaded_at || project.created_at

  return (
    <section className="page ov">
      <div className="back-link">
        <a href="#/customers">Customers</a> › <a href={`#/customers/${customer.company_id}`}>{customer.name}</a> ›{' '}
        {project.name}
      </div>

      <div className="panel cp-head">
        <div className="cp-title">
          <h1>
            {project.name} <ProjectStatus project={project} />
          </h1>
          <div className="subtitle">
            Project of {customer.name} · opened {fmtTime(project.created_at).slice(0, 10)}
            {project.closed_at ? ` · closed ${fmtTime(project.closed_at).slice(0, 10)} by ${project.closed_by}` : ''}
            {' '}· last activity {ago(last)}
          </div>
        </div>
        <div className="cp-project-actions">
          <ProjectRename project={project} onChange={onChange} />
          <ProjectAction project={project} onChange={onChange} />
          <ProjectDelete project={project} />
        </div>
      </div>

      <div className="cp-grid">
        <div className="panel">
          <h2>Project</h2>
          <dl className="cp-dl">
            <dt>Project ID</dt>
            <dd className="mono">{project.project_id}</dd>
            <dt>Customer</dt>
            <dd>{customer.name}</dd>
            <dt>Created</dt>
            <dd>{fmtTime(project.created_at)}</dd>
            <dt>Created by</dt>
            <dd>{project.created_by || '—'}</dd>
          </dl>
        </div>

        <div className="cp-main">
          <div className="panel">
            <h2>At a glance</h2>
            <dl className="cp-dl cp-glance">
              <dt>Cases</dt>
              <dd>
                {cases.length} <span className="cell-sub">{ready.length} ready</span>
              </dd>
              <dt>Flagged events</dt>
              <dd>{fmtNum(flagged)}</dd>
              <dt>Highest severity</dt>
              <dd>{highest ? <span className={`sev-tag sev-tag-${highest}`}>{SEV_EN[highest]}</span> : '—'}</dd>
            </dl>
          </div>

          <CasesPanel cases={cases} />
        </div>
      </div>

      {/* The whole investigation (specs/projects.md P4): what every case's confirmed
          events add up to, read-only - decisions are made in each case's Attack events. */}
      <ProjectTimeline project={project} />
      <ProjectPath project={project} />
    </section>
  )
}

/** Every confirmed group of every case of the project, in the order its first event
 *  happened, each naming its case (P4) - the case page's Attack timeline, project-wide. */
function ProjectTimeline({ project }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let alive = true
    getProjectTimeline(project.company_id, project.project_id)
      .then((d) => alive && setData(d))
      .catch((err) => alive && setError(err.message))
    return () => {
      alive = false
    }
  }, [project.company_id, project.project_id])
  const n = data?.findings.length || 0
  return (
    <Section icon="clock" tone={n ? 'danger' : 'muted'} title="Attack timeline of the project"
             sub={data ? `${fmtNum(n)} confirmed ${n === 1 ? 'group' : 'groups'} across ${fmtNum(data.cases.length)} `
               + `${data.cases.length === 1 ? 'case' : 'cases'}`
               + (data.undecided ? ` - ${fmtNum(data.undecided)} suggestions not decided yet` : '') : ''}>
      {error ? (
        <div className="empty">{error}</div>
      ) : !data ? (
        <div className="empty">Loading...</div>
      ) : !n ? (
        <div className="empty">No attack event confirmed yet - decide them in each case&apos;s Attack events</div>
      ) : (
        <div className="cp-section-body">
          <AttackTimelineView rows={data.findings} tacticOrder={data.tactic_order} showCase
                              findingHref={(f) => `#/finding/${f.case_id}/${encodeURIComponent(f.key)}`} />
        </div>
      )}
    </Section>
  )
}

/** The attack graph and risk ranking of the project's cases joined (P4): a host or an
 *  account is one node in every case of the customer, so what links the cases shows. */
function ProjectPath({ project }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let alive = true
    getProjectGraph(project.company_id, project.project_id)
      .then((d) => alive && setData(d))
      .catch((err) => alive && setError(err.message))
    return () => {
      alive = false
    }
  }, [project.company_id, project.project_id])
  const edges = data?.graph?.edges || []
  const shared = edges.filter((e) => (e.cases || []).length > 1).length
  const waiting = !!data?.undecided
  return (
    <Section icon="lateral-movement" tone={edges.length ? 'danger' : 'muted'} title="Attack path of the project"
             sub={!data ? '' : waiting
               ? 'Drawn once every suggestion of its cases is decided'
               : `The confirmed attack events of its cases joined - ${fmtNum(edges.length)} `
                 + `${edges.length === 1 ? 'link' : 'links'}`
                 + (shared ? `, ${fmtNum(shared)} seen in more than one case` : '')}>
      {error ? (
        <div className="empty">{error}</div>
      ) : !data ? (
        <div className="empty">Loading...</div>
      ) : waiting ? null : (
        <div className="cp-section-body">
          {edges.length ? <AttackGraph graph={data.graph} /> : <div className="empty">No confirmed attack event links two entities</div>}
          <div className="section-label">Risk ranking, over the project&apos;s cases</div>
          <RiskTables risk={data.risk || {}} />
        </div>
      )}
    </Section>
  )
}

function ProjectStatus({ project }) {
  return project.status === 'closed' ? <Badge tone="ok">Closed</Badge> : <Badge tone="info">Open</Badge>
}

/** Close an Open project - only once every suggestion of its cases is decided and
 *  every case is processed (Q110); the server says what still stands in the way -
 *  or reopen a Closed one. Manager and admin (Q113). */
function ProjectAction({ project, onChange }) {
  const { can, why } = useAccess()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const closing = project.status !== 'closed'
  const blocked = closing && !project.can_close
  const run = async () => {
    setBusy(true)
    setError('')
    try {
      await changeProject(project.company_id, project.project_id, closing ? 'close' : 'reopen')
      onChange()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="cp-project-action">
      <button type="button" className={closing ? 'btn-primary' : 'secondary'}
              disabled={busy || blocked || !can('customer:manage')}
              title={why('customer:manage') || (blocked ? `Cannot close yet: ${project.close_blocker}` : '')}
              onClick={run}>
        {busy ? '...' : closing ? 'Close project' : 'Reopen project'}
      </button>
      {blocked && <div className="cell-sub">Cannot close yet: {project.close_blocker}</div>}
      {error && <div className="lc-error">{error}</div>}
    </div>
  )
}

/** Rename the project, inline (P3): manager and admin. The name is how an upload finds
 *  a project, so the server refuses one another project of the customer already has. */
function ProjectRename({ project, onChange }) {
  const { can, why } = useAccess()
  const [editing, setEditing] = useState(false)
  const [name, setName] = useState(project.name)
  const [error, setError] = useState('')
  if (!editing) {
    return (
      <button type="button" className="secondary" disabled={!can('customer:manage')} title={why('customer:manage')}
              onClick={() => { setName(project.name); setEditing(true) }}>
        Rename
      </button>
    )
  }
  const save = async () => {
    setError('')
    try {
      await renameProject(project.company_id, project.project_id, name)
      setEditing(false)
      onChange()
    } catch (err) {
      setError(err.message)
    }
  }
  return (
    <div className="cp-rename">
      <input value={name} onChange={(e) => setName(e.target.value)} aria-label="Project name" autoFocus />
      <button type="button" className="btn-primary" disabled={!name.trim()} onClick={save}>Save</button>
      <button type="button" className="secondary" onClick={() => { setEditing(false); setError('') }}>Cancel</button>
      {error && <div className="lc-error">{error}</div>}
    </div>
  )
}

/** Delete the project with every case in it (P3): admin and manager, as a customer -
 *  what goes read from the server, the project's name typed back. */
function ProjectDelete({ project }) {
  const { can, why } = useAccess()
  const [info, setInfo] = useState(null)
  const [open, setOpen] = useState(false)
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const start = () => {
    setOpen(true)
    getProjectDeletion(project.company_id, project.project_id).then(setInfo, (err) => setError(err.message))
  }
  const confirm = async () => {
    setBusy(true)
    setError('')
    try {
      await deleteProject(project.company_id, project.project_id)
      window.location.hash = `#/customers/${project.company_id}`
    } catch (err) {
      setError(err.message)
      setBusy(false)
    }
  }
  if (!open) {
    return (
      <button type="button" className="secondary danger-outline" disabled={!can('customer:delete')}
              title={why('customer:delete')} onClick={start}>
        Delete project
      </button>
    )
  }
  const n = (v, one, many) => `${fmtNum(v)} ${v === 1 ? one : many}`
  return (
    <div className="delete-case cp-delete-project">
      {!info ? (
        <div className="muted">{error || 'Reading what would be deleted...'}</div>
      ) : (
        <>
          <div>
            Deletes the project <strong>{info.name}</strong> for good
            {info.cases
              ? `: ${n(info.cases, 'case', 'cases')} (evidence files, events, findings, AI analyses, review logs and chains of custody), ${n(info.suggestions, 'suggestion', 'suggestions')} and ${n(info.decisions, 'analyst decision', 'analyst decisions')}.`
              : '. It holds no case.'}{' '}
            Who deleted it and when, each case&apos;s record and the project&apos;s own log stay in the
            customer&apos;s deletion record.
          </div>
          {info.busy.length > 0 && (
            <div className="lc-error">
              Cannot be deleted now - wait until these are done:{' '}
              {info.busy.map((b) => `${b.file || b.case_id} (${b.reason})`).join('; ')}
            </div>
          )}
          <label>
            <span>Type <code>{info.name}</code> to confirm</span>
            <input value={typed} onChange={(e) => setTyped(e.target.value)} autoFocus spellCheck={false} />
          </label>
          <div className="delete-actions">
            <button className="danger" disabled={busy || info.busy.length > 0 || typed.trim() !== info.name.trim()}
                    onClick={confirm}>
              {busy ? 'Deleting...' : 'Delete project for good'}
            </button>
            <button className="secondary" disabled={busy} onClick={() => { setOpen(false); setTyped(''); setError('') }}>
              Cancel
            </button>
          </div>
          {error && <div className="lc-error">{error}</div>}
        </>
      )}
    </div>
  )
}

/** A case's project, changeable here (P3): manager and admin move a case into another
 *  Open project of the customer - never out of a Closed one, never while processing. */
function CaseProject({ m, projects, companyId, onChange }) {
  const { can, why } = useAccess()
  const [error, setError] = useState('')
  const current = projects.find((p) => p.project_id === m.project_id)
  const locked = current?.status === 'closed'
  const busy = m.status === 'queued' || m.status === 'processing'
  const reason = why('customer:manage') || (locked ? `"${current.name}" is closed - reopen it to move a case out`
    : busy ? 'The case is being processed' : '')
  const move = async (e) => {
    setError('')
    try {
      await moveCase(companyId, e.target.value, m.case_id)
      onChange()
    } catch (err) {
      setError(err.message)
    }
  }
  return (
    <>
      <select className="cp-case-project" value={m.project_id || ''} aria-label={`Project of ${m.original_filename}`}
              disabled={!can('customer:manage') || locked || busy} title={reason} onChange={move}>
        {!m.project_id && <option value="" disabled>No project</option>}
        {projects.map((p) => (
          <option key={p.project_id} value={p.project_id} disabled={p.status === 'closed' && p.project_id !== m.project_id}>
            {p.name}{p.status === 'closed' ? ' (closed)' : ''}
          </option>
        ))}
      </select>
      {error && <div className="lc-error">{error}</div>}
    </>
  )
}

function ProjectsPanel({ companyId, projects, cases }) {
  const unfiled = cases.filter((m) => !m.project_id).length
  return (
    <div className="panel">
      <h2>
        Projects <span className="muted mono">{projects.length}</span>
      </h2>
      <div className="table-scroll">
        <table className="ov-table">
          <thead>
            <tr>
              <th>Project</th>
              <th>Status</th>
              <th>Opened</th>
              <th>Closed</th>
              <th className="num">Cases</th>
              <th className="num">Not decided</th>
              <th>Highest not decided</th>
              <th>Last activity</th>
            </tr>
          </thead>
          <tbody>
            {!projects.length && (
              <tr>
                <td colSpan={8} className="empty">
                  No projects yet - choose or add one when uploading
                </td>
              </tr>
            )}
            {/* Open first, then the newest (projects.summary). */}
            {projects.map((p) => {
              const own = cases.filter((m) => m.project_id === p.project_id)
              return (
                <tr key={p.project_id}>
                  <td>
                    <a href={`#/customers/${companyId}/projects/${p.project_id}`}>{p.name}</a>
                  </td>
                  <td><ProjectStatus project={p} /></td>
                  <td className="mono muted">{fmtTime(p.created_at).slice(0, 10)}</td>
                  <td className="mono muted">{p.closed_at ? fmtTime(p.closed_at).slice(0, 10) : '—'}</td>
                  <td className="num mono">{p.cases}</td>
                  <td className="num mono">{fmtNum(p.unreviewed)} <span className="cell-sub">of {fmtNum(p.reviewable)}</span></td>
                  <td>{p.highest ? <span className={`sev-tag sev-tag-${p.highest}`}>{SEV_EN[p.highest] || p.highest}</span> : '—'}</td>
                  <td className="mono muted">{ago(own[0]?.uploaded_at || p.created_at)}</td>
                </tr>
              )
            })}
            {/* Cases from before a project was required (Q112): movable into one (P3). */}
            {unfiled > 0 && (
              <tr>
                <td className="muted">No project</td>
                <td colSpan={3} className="cell-sub">uploaded before a project was required</td>
                <td className="num mono">{unfiled}</td>
                <td colSpan={3} />
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function CasesPanel({ cases, showProject = false, projects = [], companyId, onChange }) {
  const cols = showProject ? 8 : 7
  return (
    <div className="panel">
      <h2>
        Cases <span className="muted mono">{cases.length}</span>
      </h2>
      <div className="table-scroll">
        <table className="ov-table">
          <thead>
            <tr>
              <th>Uploaded</th>
              <th>File</th>
              {showProject && <th>Project</th>}
              <th>Uploaded by</th>
              <th>Severity</th>
              <th className="num">Flagged</th>
              <th>Status</th>
              <th>AI analysis</th>
            </tr>
          </thead>
          <tbody>
            {!cases.length && (
              <tr>
                <td colSpan={cols} className="empty">
                  No cases yet
                </td>
              </tr>
            )}
            {cases.map((m) => {
              const isReady = m.status === 'ready'
              return (
                <tr key={m.case_id}>
                  <td className="mono muted">{fmtTime(m.uploaded_at)}</td>
                  <td>
                    {isReady ? <a href={`#/case/${m.case_id}`}>{m.original_filename}</a> : m.original_filename}
                  </td>
                  {showProject && (
                    <td><CaseProject m={m} projects={projects} companyId={companyId} onChange={onChange} /></td>
                  )}
                  <td>{m.evidence?.recorded_by || '—'}</td>
                  <td>{isReady ? <SeverityPill severity={m.severity} /> : '—'}</td>
                  <td className="num mono">{isReady ? fmtNum(m.flagged_count) : '—'}</td>
                  <td>
                    <StatusBadge status={m.status} error={m.error} />
                  </td>
                  <td>{m.has_analysis ? 'Yes' : '—'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/** The most severe level among the ready cases, or null. */
function highestOf(cases) {
  const levels = cases.filter((m) => m.status === 'ready').map((m) => severityBucket(m.severity))
  return SEVS.find((s) => levels.includes(s)) || null
}

/** "Big Fish Co" -> "BF"; one word -> its first two letters ("SUMMIT" -> "SU"). */
function initials(name) {
  const words = (name || '').trim().split(/\s+/).filter(Boolean)
  const text = words.length > 1 ? words[0][0] + words[1][0] : (words[0] || '?').slice(0, 2)
  return text.toUpperCase()
}

/** The log sources the customer's files were read as (logsources.py
 *  profiles), across plain files, line logs and zip members. */
function logSources(cases) {
  const names = new Set()
  const add = (mp) => {
    if (!mp) return
    if (mp.name) names.add(mp.name)
    for (const p of mp.line_profiles || []) names.add(p.name)
  }
  for (const m of cases) {
    add(m.mapping)
    for (const mem of m.members || []) add(mem.mapping)
  }
  return [...names].sort()
}
