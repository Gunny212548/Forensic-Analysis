import { useCallback, useEffect, useState } from 'react'
import { listCompanies, listFindings } from '../api.js'
import { LEVEL_EN, fmtNum, shortTs } from '../format.js'

const STATUSES = ['Open', 'Investigating', 'Contained', 'Resolved']
const SEVERITIES = ['critical', 'high']
const PAGE = 50

/** figma-export/Incidents.svg, which the console calls Findings (FR-4.4): every
 *  finding that entered the status workflow, across cases. Only high and
 *  critical findings enter it (lifecycle.py); the rest stay on their case page,
 *  and the footnote says so rather than letting the table read as "all of them".
 *
 *  A row opens its case on the Review tab, scrolled to the finding. */
export default function Findings({ areaId }) {
  const [companies, setCompanies] = useState([])
  const [companyId, setCompanyId] = useState('')
  const [status, setStatus] = useState('')
  const [severity, setSeverity] = useState('')
  const [area, setArea] = useState(areaId || '')
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
      setData(await listFindings({ companyId, status, severity, area, q, limit: PAGE, offset }))
      setError('')
    } catch (err) {
      setError(err.message)
    }
  }, [companyId, status, severity, area, q, offset])

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
  const from = data.total ? data.offset + 1 : 0
  const to = Math.min(data.offset + data.limit, data.total)

  return (
    <section className="page ov">
      <div className="top-bar">
        <div>
          <h1>Findings</h1>
          <div className="subtitle">
            <span className="live-dot" /> {fmtNum(data.open_count)} open of {fmtNum(data.scope_total)} in the
            workflow{scope ? ` - ${scope.name}` : ' - all customers'}
          </div>
        </div>
        <div className="actions">
          <button type="button" className="secondary" onClick={load}>
            Refresh
          </button>
        </div>
      </div>

      <div className="fd-counts" aria-label="Findings per severity">
        {SEVERITIES.map((s) => (
          <button
            type="button"
            key={s}
            className={`fd-count${severity === s ? ' active' : ''}`}
            onClick={() => {
              setSeverity(severity === s ? '' : s)
              setOffset(0)
            }}
            title={severity === s ? 'Show all severities' : `Show only ${LEVEL_EN[s]} findings`}
          >
            <span className={`sev-tag sev-tag-${s}`}>{LEVEL_EN[s]}</span>
            <strong>{fmtNum(data.by_severity[s] || 0)}</strong>
          </button>
        ))}
        <span className="fd-status-counts muted">
          {STATUSES.map((s) => `${s} ${fmtNum(data.by_status[s] || 0)}`).join(' · ')}
        </span>
      </div>

      <div className="panel">
        <div className="filter-bar fd-filters">
          <select value={companyId} onChange={pick(setCompanyId)} aria-label="Customer">
            <option value="">All customers</option>
            {companies.map((c) => (
              <option value={c.company_id} key={c.company_id}>
                {c.name}
              </option>
            ))}
          </select>
          <select value={status} onChange={pick(setStatus)} aria-label="Status">
            <option value="">Any status</option>
            {STATUSES.map((s) => (
              <option value={s} key={s}>
                {s}
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
            placeholder="Search id, host, rule, file, assignee..."
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
                <th>Status</th>
                <th>Log type</th>
                <th>Source file</th>
                <th>Assignee</th>
                <th>Detected</th>
              </tr>
            </thead>
            <tbody>
              {!data.rows.length && (
                <tr>
                  <td colSpan={9} className="empty">
                    {data.scope_total
                      ? 'No finding matches these filters'
                      : 'No finding has entered the workflow yet - upload a log and process it'}
                  </td>
                </tr>
              )}
              {data.rows.map((r) => (
                <tr key={`${r.case_id}|${r.key}`}>
                  <td className="mono">
                    <a
                      className="table-link"
                      href={`#/result/${r.case_id}/${encodeURIComponent(r.key)}`}
                      title="Open this finding in its case"
                    >
                      {r.fd}
                    </a>
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
                    <span className={`lc-${r.status.toLowerCase()}`}>
                      <span className="lc-status">{r.status}</span>
                    </span>
                  </td>
                  <td>{r.log_type}</td>
                  <td className="mono">{r.source_file}</td>
                  <td>{r.assignee ? r.assignee : <span className="muted">unassigned</span>}</td>
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
          Only high and critical findings enter the status workflow; lower ones stay on their case page. The
          counts above describe the selected customer, before the status, severity and search filters. Times
          are GMT+7.
        </div>
      </div>
    </section>
  )
}
