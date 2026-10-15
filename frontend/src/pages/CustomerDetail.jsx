import { useEffect, useState } from 'react'
import { getOverview, listCases, listCompanies } from '../api.js'
import { ago, fmtNum, fmtTime } from '../format.js'
import { SeverityPill, StatusBadge } from '../components/common.jsx'
import { Kpi } from './Overview.jsx'

/** One customer, opened from the Customers list: since when, how much,
 *  which log sources, and every case. Read-only, like the list. */
export default function CustomerDetail({ companyId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let alive = true
    Promise.all([listCompanies(), getOverview(companyId), listCases(companyId)])
      .then(([companies, overview, cases]) => {
        if (!alive) return
        const customer = companies.find((c) => c.company_id === companyId)
        if (!customer) setError('Customer not found')
        else setData({ customer, overview, cases })
      })
      .catch((err) => alive && setError(err.message))
    return () => {
      alive = false
    }
  }, [companyId])

  if (error) return <div className="panel empty">Could not load the customer: {error}</div>
  if (!data) return <div className="empty">Loading...</div>

  const { customer, overview, cases } = data
  const t = overview.totals
  const ready = cases.filter((m) => m.status === 'ready')
  const analysed = ready.filter((m) => m.has_analysis).length
  const lastActivity = overview.recent[0]?.ts || cases[0]?.uploaded_at || customer.created_at

  return (
    <section className="page ov">
      <div className="top-bar">
        <div>
          <div className="back-link">
            <a href="#/customers">Customers</a> › {customer.name}
          </div>
          <h1>{customer.name}</h1>
          <div className="subtitle">
            Onboarded {fmtTime(customer.created_at)} · last activity {ago(lastActivity)}
          </div>
        </div>
        <div className="actions">
          <a className="btn-secondary" href={`#/dashboard/${companyId}`}>
            Open this customer&apos;s dashboard
          </a>
        </div>
      </div>

      <div className="kpis">
        <Kpi
          label="Cases"
          value={t.cases}
          sub={`${t.ready} ready · ${t.processing} processing · ${t.failed} failed`}
          tone="danger"
        />
        <Kpi label="Findings" value={fmtNum(t.reviewable)} sub={`${fmtNum(t.unreviewed)} awaiting review`} tone="ok" />
        <Kpi
          label="Flagged events"
          value={fmtNum(t.findings_critical + t.findings_high + t.findings_medium + t.findings_low)}
          sub={`${fmtNum(t.findings_critical)} critical · ${fmtNum(t.findings_high)} high`}
          tone="warn"
        />
        {/* No report feature exists yet (Reports page, IAI-55); the AI
            narrative per case is the nearest thing, and is named as such. */}
        <Kpi label="AI analyses" value={analysed} sub={`of ${ready.length} ready cases`} tone="info" />
      </div>

      <div className="panel">
        <h2>Log sources received</h2>
        <div className="format-chips">
          {logSources(cases).map((s) => (
            <span className="chip" key={s}>
              {s}
            </span>
          ))}
          {!logSources(cases).length && <span className="muted">None identified yet</span>}
        </div>
      </div>

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
                  <td colSpan={7} className="empty">
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
    </section>
  )
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
