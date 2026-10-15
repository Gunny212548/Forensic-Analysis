import { useEffect, useState } from 'react'
import { getOverview, listCases, listCompanies, listProjects } from '../api.js'
import { ago, fmtNum, fmtTime, severityBucket } from '../format.js'
import { SeverityPill, StatusBadge } from '../components/common.jsx'

const SEVS = ['critical', 'high', 'medium', 'low']
const SEV_EN = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }

/** One customer's profile, opened from the Customers list: who they are,
 *  since when, what they sent, their projects and every case - or, with
 *  `projectId`, one of those projects. Read-only, like the list. */
export default function CustomerDetail({ companyId, projectId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

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
  }, [companyId])

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
            </dl>
          </div>

          <ProjectsPanel companyId={companyId} projects={projects} cases={cases} />

          <CasesPanel cases={cases} showProject />
        </div>
      </div>
    </section>
  )
}

/** One investigation of the customer and the cases uploaded for it. */
function ProjectView({ customer, project, cases }) {
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
          <h1>{project.name}</h1>
          <div className="subtitle">
            Project of {customer.name} · created {fmtTime(project.created_at).slice(0, 10)} · last activity{' '}
            {ago(last)}
          </div>
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
    </section>
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
              <th>Created</th>
              <th className="num">Cases</th>
              <th>Highest severity</th>
              <th>Last activity</th>
            </tr>
          </thead>
          <tbody>
            {!projects.length && (
              <tr>
                <td colSpan={5} className="empty">
                  No projects yet - choose or add one when uploading
                </td>
              </tr>
            )}
            {projects.map((p) => {
              const own = cases.filter((m) => m.project_id === p.project_id)
              const highest = highestOf(own)
              return (
                <tr key={p.project_id}>
                  <td>
                    <a href={`#/customers/${companyId}/projects/${p.project_id}`}>{p.name}</a>
                  </td>
                  <td className="mono muted">{fmtTime(p.created_at).slice(0, 10)}</td>
                  <td className="num mono">{own.length}</td>
                  <td>{highest ? <span className={`sev-tag sev-tag-${highest}`}>{SEV_EN[highest]}</span> : '—'}</td>
                  <td className="mono muted">{ago(own[0]?.uploaded_at || p.created_at)}</td>
                </tr>
              )
            })}
            {projects.length > 0 && unfiled > 0 && (
              <tr>
                <td className="muted">No project</td>
                <td />
                <td className="num mono">{unfiled}</td>
                <td />
                <td />
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function CasesPanel({ cases, showProject = false }) {
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
                    {isReady ? <a href={`#/result/${m.case_id}`}>{m.original_filename}</a> : m.original_filename}
                  </td>
                  {showProject && <td>{m.project_name || '—'}</td>}
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
