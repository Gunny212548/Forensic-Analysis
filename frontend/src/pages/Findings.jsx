import { useCallback, useEffect, useState } from 'react'
import { listCompanies, listFindings, listProjects } from '../api.js'
import { LEVEL_EN, fmtNum, shortTs } from '../format.js'
import { StatTile } from '../components/cards.jsx'

// The analyst's decision (review.py), as the case's Attack events shows it. It
// replaced the status workflow's filter on 2026-10-27: Respond left (gotcha #54),
// nothing on screen moves a status or sets an assignee, so every finding stayed
// Open and unassigned.
const DECISIONS = [['Unreviewed', 'Not decided'], ['Accepted', 'Accepted'], ['Modified', 'Modified'], ['Rejected', 'Rejected']]
const DECISION_EN = Object.fromEntries(DECISIONS)
const DECISION_TONE = { Unreviewed: 'warn', Accepted: 'ok', Modified: 'info', Rejected: 'muted' }
const SEVERITIES = ['critical', 'high']
const SEV_TONE = { critical: 'danger', high: 'warn' }
const PAGE = 50

/** figma-export/Incidents.svg, which the console calls Findings (FR-4.4): every
 *  high and critical finding (each has an FD id), across cases, with the
 *  analyst's decision on it. The rest stay on their case page, and the footnote
 *  says so rather than letting the table read as "all of them".
 *
 *  A row opens its case on the Review tab, scrolled to the finding. */
/** `param` is an area id, or a query string - severity, decision, area. */
function initialFilters(param) {
  if (!param) return {}
  if (!param.includes('=')) return { area: param }
  const q = new URLSearchParams(param)
  return { area: q.get('area') || '', severity: q.get('severity') || '', decision: q.get('decision') || '',
    companyId: q.get('company_id') || '', projectId: q.get('project_id') || '' }
}

export default function Findings({ param }) {
  const init = initialFilters(param)
  const [companies, setCompanies] = useState([])
  // A link from a customer-scoped Overview carries the customer, so the list
  // opens on the findings the number that was clicked counted.
  const [companyId, setCompanyId] = useState(init.companyId || '')
  // One investigation of that customer (specs/projects.md P2).
  const [projectId, setProjectId] = useState(init.projectId || '')
  const [projects, setProjects] = useState([])
  const [decision, setDecision] = useState(init.decision || '')
  const [severity, setSeverity] = useState(init.severity || '')
  const [area, setArea] = useState(init.area || '')
  const [text, setText] = useState('')
  const [q, setQ] = useState('')
  const [offset, setOffset] = useState(0)
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    listCompanies()
      .then(setCompanies)
      .catch(() => setCompanies([]))
  }, [])

  useEffect(() => {
    if (!companyId) return setProjects([])
    listProjects(companyId)
      .then(setProjects)
      .catch(() => setProjects([]))
  }, [companyId])

  // Search waits for a pause in typing instead of asking the server per key.
  useEffect(() => {
    const t = setTimeout(() => {
      setQ(text.trim())
      setOffset(0)
    }, 300)
    return () => clearTimeout(t)
  }, [text])

  const load = useCallback(async () => {
    try {
      setData(await listFindings({ companyId, projectId, decision, severity, area, q, limit: PAGE, offset }))
      setError('')
    } catch (err) {
      setError(err.message)
    }
  }, [companyId, projectId, decision, severity, area, q, offset])

  useEffect(() => {
    load()
  }, [load])

  function pick(setter) {
    return (e) => {
      setter(e.target.value)
      setOffset(0)
    }
  }

  if (error && !data) return <div className="panel empty">Could not load findings: {error}</div>
  if (!data) return <div className="empty">Loading...</div>

  const scope = companies.find((c) => c.company_id === companyId)
  const scopeProject = projects.find((p) => p.project_id === projectId)
  const from = data.total ? data.offset + 1 : 0
  const to = Math.min(data.offset + data.limit, data.total)

  return (
    <section className="page ov">
      <div className="top-bar">
        <div>
          <h1>Findings</h1>
          <div className="subtitle">
            <span className="live-dot" /> {fmtNum(data.undecided_count)} not decided of {fmtNum(data.scope_total)} high
            and critical findings{scope ? ` - ${scope.name}` : ' - all customers'}
            {scopeProject ? `, project ${scopeProject.name}` : ''}
          </div>
        </div>
        <div className="actions">
          <button type="button" className="secondary" onClick={load}>
            Refresh
          </button>
        </div>
      </div>

      {/* The two levels are filters as well as counts: a tile switches its level on and off. */}
      <div className="ui-stat-grid" aria-label="Findings per severity">
        <StatTile icon="findings" tone={data.undecided_count ? 'warn' : 'ok'} value={fmtNum(data.undecided_count)}
                  label="Not decided" active={decision === 'Unreviewed'}
                  title={decision === 'Unreviewed' ? 'Show every decision' : 'Show only the findings not decided'}
                  onClick={() => {
                    setDecision(decision === 'Unreviewed' ? '' : 'Unreviewed')
                    setOffset(0)
                  }} />
        {SEVERITIES.map((s) => (
          <StatTile
            key={s}
            icon="shield-alert"
            tone={SEV_TONE[s]}
            value={fmtNum(data.by_severity[s] || 0)}
            label={LEVEL_EN[s]}
            active={severity === s}
            title={severity === s ? 'Show all severities' : `Show only ${LEVEL_EN[s]} findings`}
            onClick={() => {
              setSeverity(severity === s ? '' : s)
              setOffset(0)
            }}
          />
        ))}
        <StatTile icon="cases" tone="info" value={fmtNum(data.scope_total)} label="High and critical" />
      </div>
      <div className="fd-status-counts muted">
        {DECISIONS.map(([d, label]) => `${label} ${fmtNum(data.by_decision[d] || 0)}`).join(' · ')}
      </div>

      <div className="panel">
        <div className="filter-bar fd-filters">
          <select value={companyId} aria-label="Customer"
                  onChange={(e) => {
                    setCompanyId(e.target.value)
                    setProjectId('') // a project is one customer's
                    setOffset(0)
                  }}>
            <option value="">All customers</option>
            {companies.map((c) => (
              <option value={c.company_id} key={c.company_id}>
                {c.name}
              </option>
            ))}
          </select>
          {companyId && (
            <select value={projectId} onChange={pick(setProjectId)} aria-label="Project">
              <option value="">All projects</option>
              {projects.map((p) => (
                <option value={p.project_id} key={p.project_id}>
                  {p.name}{p.status === 'closed' ? ' (closed)' : ''}
                </option>
              ))}
            </select>
          )}
          <select value={decision} onChange={pick(setDecision)} aria-label="Decision">
            <option value="">Any decision</option>
            {DECISIONS.map(([d, label]) => (
              <option value={d} key={d}>
                {label}
              </option>
            ))}
          </select>
          <select value={area} onChange={pick(setArea)} aria-label="Detection area">
            <option value="">Any area</option>
            {(data.areas || []).map((a) => (
              <option value={a.id} key={a.id}>
                {a.name}
              </option>
            ))}
          </select>
          <select value={severity} onChange={pick(setSeverity)} aria-label="Severity">
            <option value="">Any severity</option>
            {SEVERITIES.map((s) => (
              <option value={s} key={s}>
                {LEVEL_EN[s]}
              </option>
            ))}
          </select>
          <input
            type="text"
            className="fd-search"
            placeholder="Search id, host, rule, file..."
            aria-label="Search findings"
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
        </div>

        <div className="table-scroll">
          <table className="ov-table fd-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Finding</th>
                <th>Customer</th>
                <th>Severity</th>
                <th>Decision</th>
                <th>Log type</th>
                <th>Source file</th>
                <th>Detected</th>
              </tr>
            </thead>
            <tbody>
              {!data.rows.length && (
                <tr>
                  <td colSpan={8} className="empty">
                    {data.scope_total
                      ? 'No finding matches these filters'
                      : 'No high or critical finding yet - upload a log and process it'}
                  </td>
                </tr>
              )}
              {data.rows.map((r) => (
                <tr key={`${r.case_id}|${r.key}`}>
                  <td className="mono">
                    <a
                      className="table-link"
                      href={`#/finding/${r.case_id}/${encodeURIComponent(r.key)}`}
                      title="Open this finding"
                    >
                      {r.fd}
                    </a>
                    {r.evidence_problem && (
                      <div className="cell-sub ev-bad" title="The case's evidence file no longer matches its acquisition digest">
                        evidence changed
                      </div>
                    )}
                  </td>
                  <td>
                    <div title={r.descr}>{r.name}</div>
                    <div className="cell-sub mono">{r.host || '—'}</div>
                  </td>
                  <td>
                    {r.company_name}
                    {r.project_name && <div className="cell-sub">{r.project_name}</div>}
                  </td>
                  <td>
                    <span className={`sev-tag sev-tag-${r.level}`}>{LEVEL_EN[r.level]}</span>
                  </td>
                  <td>
                    <span className={`ui-badge tone-${DECISION_TONE[r.review] || 'muted'}`}>
                      {DECISION_EN[r.review] || r.review}
                    </span>
                  </td>
                  <td>{r.log_type}</td>
                  <td className="mono">{r.source_file}</td>
                  <td className="mono muted">{shortTs(r.detected)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="fd-pager">
          <span className="muted">
            {data.total ? `${fmtNum(from)}-${fmtNum(to)} of ${fmtNum(data.total)}` : '0 findings'}
          </span>
          <button
            type="button"
            className="secondary"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE))}
          >
            Previous
          </button>
          <button
            type="button"
            className="secondary"
            disabled={to >= data.total}
            onClick={() => setOffset(offset + PAGE)}
          >
            Next
          </button>
        </div>
        <div className="field-hint cust-note">
          Only high and critical findings get an FD id and are listed here; lower ones stay on their case page.
          A decision is taken on the case&apos;s Attack events. The counts above describe the selected customer,
          before the decision, severity and search filters. Times are GMT+7.
        </div>
      </div>
    </section>
  )
}
