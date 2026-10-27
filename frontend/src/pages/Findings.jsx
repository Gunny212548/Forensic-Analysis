import { useCallback, useEffect, useState } from 'react'
import { listCompanies, listFindings } from '../api.js'
import { LEVEL_EN, fmtNum, shortTs } from '../format.js'
import { StatTile } from '../components/cards.jsx'

const STATUSES = ['Open', 'Investigating', 'Contained', 'Resolved']
const SEVERITIES = ['critical', 'high']
const SEV_TONE = { critical: 'danger', high: 'warn' }
const PAGE = 50

/** figma-export/Incidents.svg, which the console calls Findings (FR-4.4): every
 *  finding that entered the status workflow, across cases. Only high and
 *  critical findings enter it (lifecycle.py); the rest stay on their case page,
 *  and the footnote says so rather than letting the table read as "all of them".
 *
 *  A row opens its case on the Review tab, scrolled to the finding. */
/** `param` is an area id, or a query string - severity, status, area, unassigned. */
function initialFilters(param) {
  if (!param) return {}
  if (!param.includes('=')) return { area: param }
  const q = new URLSearchParams(param)
  return { area: q.get('area') || '', severity: q.get('severity') || '', status: q.get('status') || '',
    unassigned: q.get('unassigned') === '1', companyId: q.get('company_id') || '' }
}

export default function Findings({ param }) {
  const init = initialFilters(param)
  const [companies, setCompanies] = useState([])
  // A link from a customer-scoped Overview carries the customer, so the list
  // opens on the findings the number that was clicked counted.
  const [companyId, setCompanyId] = useState(init.companyId || '')
  const [status, setStatus] = useState(init.status || '')
  const [severity, setSeverity] = useState(init.severity || '')
  const [area, setArea] = useState(init.area || '')
  const [unassigned, setUnassigned] = useState(Boolean(init.unassigned))
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
      setData(await listFindings({ companyId, status, severity, area, unassigned, q, limit: PAGE, offset }))
      setError('')
    } catch (err) {
      setError(err.message)
    }
  }, [companyId, status, severity, area, unassigned, q, offset])

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

      {/* The two levels are filters as well as counts: a tile switches its level on and off. */}
      <div className="ui-stat-grid" aria-label="Findings per severity">
        <StatTile icon="findings" tone={data.open_count ? 'danger' : 'ok'} value={fmtNum(data.open_count)}
                  label="Not resolved" />
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
        <StatTile icon="cases" tone="info" value={fmtNum(data.scope_total)} label="In the workflow" />
      </div>
      <div className="fd-status-counts muted">
        {STATUSES.map((s) => `${s} ${fmtNum(data.by_status[s] || 0)}`).join(' · ')}
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
            <option value="open">Not resolved</option>
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
          <select
            value={unassigned ? 'none' : ''}
            onChange={(e) => {
              setUnassigned(e.target.value === 'none')
              setOffset(0)
            }}
            aria-label="Assignee"
          >
            <option value="">Any assignee</option>
            <option value="none">Unassigned</option>
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
