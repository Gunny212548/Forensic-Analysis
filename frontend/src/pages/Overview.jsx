import { useCallback, useEffect, useMemo, useState } from 'react'
import { getOverview } from '../api.js'
import { ago, fmtNum, severityBucket } from '../format.js'

const POLL_MS = 15000
const SEVS = ['critical', 'high', 'medium', 'low']
const SEV_EN = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None' }
const STATUS_EN = { queued: 'Queued', processing: 'Processing', ready: 'Ready', failed: 'Failed' }
const ROLE_EN = { sources: 'source', destinations: 'destination', accounts: 'account' }

/** The Overview (redesigned 2026-10-19 at the user's request; the cards follow a
 *  reference the user supplied, in this console's light palette).
 *
 *  It leads with six detection areas (app/services/areas.py): one card each,
 *  showing the findings in the status workflow that are not yet Resolved, how
 *  many are still Open and how many findings the area holds in total (by level),
 *  and when they were first seen. Every figure comes from GET /api/overview -
 *  never a placeholder - and a card opens the Findings page on that area. Below
 *  them sit what the page already had: the review backlog, severity, top
 *  affected hosts, activity, techniques and the case list (IAI-20). */
export default function Overview({ companyId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [sev, setSev] = useState('all')
  const [q, setQ] = useState('')

  const load = useCallback(async () => {
    try {
      setData(await getOverview(companyId))
      setError('')
    } catch (err) {
      setError(err.message)
    }
  }, [companyId])

  useEffect(() => {
    load()
    const t = setInterval(load, POLL_MS)
    return () => clearInterval(t)
  }, [load])

  const cases = useMemo(() => {
    const list = data?.cases || []
    const needle = q.trim().toLowerCase()
    return list.filter((c) => {
      const b = c.status === 'ready' ? severityBucket(c.severity) : null
      if (sev !== 'all' && b !== sev) return false
      if (!needle) return true
      return [c.case_id, c.original_filename, c.company_name]
        .some((v) => (v || '').toLowerCase().includes(needle))
    })
  }, [data, sev, q])

  if (error && !data) return <div className="panel empty">Could not load the overview: {error}</div>
  if (!data) return <div className="empty">Loading...</div>

  const t = data.totals
  const cs = data.case_severity
  const reviewedPct = t.reviewable ? Math.round(((t.reviewable - t.unreviewed) / t.reviewable) * 100) : 0
  const scoped = (data.customer_options || []).find((c) => c.company_id === data.company_id)

  return (
    <section className="page ov">
      <div className="top-bar">
        <div>
          <h1>Security Operations Overview</h1>
          <div className="subtitle">
            <span className="live-dot" /> {t.cases} cases · updated {ago(data.generated_at)}
          </div>
          {/* Whose data every figure below is - named, never just counted. */}
          <div className="ov-scope">
            {scoped ? (
              <>
                Customer: <strong>{scoped.name}</strong>
              </>
            ) : (
              <>
                All customers:{' '}
                <strong>{(data.customer_options || []).map((c) => c.name).join(', ') || 'none yet'}</strong>
              </>
            )}
          </div>
        </div>
        <div className="actions">
          {/* Each customer's cases live in that customer's own store
              (storage.py); this picks which store the page reads. */}
          <select
            className="ov-customer"
            aria-label="Customer"
            value={data.company_id || ''}
            onChange={(e) => {
              window.location.hash = e.target.value ? `#/dashboard/${e.target.value}` : '#/dashboard'
            }}
          >
            <option value="">All customers</option>
            {(data.customer_options || []).map((c) => (
              <option key={c.company_id} value={c.company_id}>
                {c.name}
              </option>
            ))}
          </select>
          <button type="button" className="secondary" onClick={load}>
            Refresh
          </button>
          <a className="btn-primary" href="#/upload">
            Upload log
          </a>
        </div>
      </div>

      <div className="kpis">
        <Kpi
          label="Open findings"
          value={fmtNum(t.open_findings)}
          chip={t.new_findings ? `${fmtNum(t.new_findings)} new` : null}
          chipTone="danger"
          sub="high and critical, not yet Resolved"
          tone="danger"
        />
        <Kpi
          label="Findings awaiting review"
          value={t.unreviewed}
          chip={t.reviewable ? `${reviewedPct}% reviewed` : null}
          chipTone="ok"
          sub={`of ${t.reviewable} findings · ${t.cases_with_unreviewed} cases`}
          tone="ok"
        />
        <Kpi
          label="Cases"
          value={t.cases}
          chip={t.uploaded_today ? `+${t.uploaded_today} today` : null}
          chipTone="danger"
          sub={`${cs.critical} critical · ${cs.high} high · ${cs.medium} medium`}
          tone="warn"
        />
        <Kpi
          label="Flagged events"
          value={fmtNum(t.findings_critical + t.findings_high + t.findings_medium + t.findings_low)}
          sub={`${fmtNum(t.findings_critical)} critical · ${fmtNum(t.findings_high)} high`}
          tone="info"
        />
      </div>

      <div className="panel">
        <div className="area-title">
          <h2>Detection areas</h2>
          <span className="muted">
            {data.trend_days.length
              ? `trend: findings first seen per day, ${data.trend_days[0]} to ${data.trend_days[data.trend_days.length - 1]}`
              : 'no findings yet'}
          </span>
        </div>
        <div className="area-grid">
          {data.areas.map((a) => (
            <AreaCard key={a.id} area={a} days={data.trend_days} />
          ))}
        </div>
        <div className="field-hint cust-note">
          The number is findings in the status workflow (high and critical) that are not yet Resolved. New is
          those still Open; Total is every finding of the area by level, workflow or not. A card opens the
          Findings page on that area.
        </div>
      </div>

      <div className="ov-row">
        <div className="panel ov-chart-panel">
          <h2>Cases uploaded per day</h2>
          <DailyChart days={data.daily} />
        </div>
        <div className="panel ov-side">
          <h2>Severity breakdown</h2>
          <SeverityBars counts={cs} />
          <div className="section-label">Top affected hosts &amp; accounts</div>
          {!data.top_entities.length && <div className="empty">No findings yet</div>}
          {data.top_entities.map((e) => (
            <div className="ov-line" key={`${e.customer}|${e.role}|${e.entity}`}>
              <span>
                <span className="cust-tag">{e.customer}</span>
                <span className="mono">{e.entity}</span>{' '}
                <span className="muted">{ROLE_EN[e.role] || e.role}</span>
              </span>
              <span>
                {e.cases} {e.cases === 1 ? 'case' : 'cases'}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="panel">
        <div className="ov-table-head">
          <h2>
            Findings <span className="muted mono">{cases.length} shown</span>
          </h2>
        </div>
        <div className="ov-filters">
          {['all', ...SEVS].map((s) => (
            <button
              type="button"
              key={s}
              className={`chip-btn${sev === s ? ' active' : ''}`}
              onClick={() => setSev(s)}
            >
              {s === 'all' ? 'All' : SEV_EN[s]}
            </button>
          ))}
          <input
            type="text"
            className="ov-search"
            placeholder="Search cases, files, customers..."
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <div className="table-scroll">
          <table className="ov-table">
            <thead>
              <tr>
                <th>Case ID</th>
                <th>File</th>
                <th>Customer</th>
                <th className="num">Events</th>
                <th className="num">Flagged</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {!cases.length && (
                <tr>
                  <td colSpan={8} className="empty">
                    {data.cases.length ? 'No case matches this filter' : 'No cases yet - upload a log to start'}
                  </td>
                </tr>
              )}
              {cases.map((c) => {
                const ready = c.status === 'ready'
                const b = ready ? severityBucket(c.severity) : null
                const open = () => ready && (window.location.hash = `#/result/${c.case_id}`)
                return (
                  <tr key={c.case_id} className={ready ? 'clickable' : ''} onClick={open}>
                    <td className="mono muted">{c.case_id.slice(-8)}</td>
                    <td>
                      {ready ? <a href={`#/result/${c.case_id}`}>{c.original_filename}</a> : c.original_filename}
                      <div className="cell-sub">{c.file_kind}</div>
                    </td>
                    <td>
                      {c.company_name || '—'}
                      {c.project_name && <div className="cell-sub">{c.project_name}</div>}
                    </td>
                    <td className="num mono">{ready ? fmtNum(c.total_rows) : '—'}</td>
                    <td className="num mono">{ready ? fmtNum(c.flagged_count) : '—'}</td>
                    <td>{b ? <span className={`sev-tag sev-tag-${b}`}>{SEV_EN[b]}</span> : '—'}</td>
                    <td>
                      <span className={`status-pill st-${c.status}`} title={c.error || ''}>
                        {STATUS_EN[c.status] || c.status}
                        {c.status === 'processing' && c.progress
                          ? ` ${c.progress.estimated ? '~' : ''}${c.progress.pct}%`
                          : ''}
                      </span>
                    </td>
                    <td className="mono muted">{ago(c.uploaded_at)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="ov-row">
        <div className="panel ov-activity">
          <h2>Recent activity</h2>
          {!data.recent.length && <div className="empty">Nothing yet</div>}
          <ul className="activity">
            {data.recent.map((r, i) => (
              <li key={i} className={`act-${r.level || 'muted'}`}>
                <a href={`#/result/${r.case_id}`}>{r.text}</a>
                {r.customer && <span className="cust-tag cust-tag-after">{r.customer}</span>}
                <div className="mono muted">{ago(r.ts)}</div>
              </li>
            ))}
          </ul>
        </div>
        <div className="panel ov-side">
          <h2>
            Techniques observed <span className="muted mono">MITRE ATT&amp;CK</span>
          </h2>
          {!data.techniques.length && <div className="empty">No techniques yet</div>}
          <div className="tech-grid">
            {data.techniques.map((tq) => (
              <div className="tech-card" key={tq.id}>
                <div className="mono accent">{tq.id}</div>
                <div>{tq.name || '—'}</div>
                <div className="tech-customers">
                  {(tq.customers || []).map((c) => (
                    <span className="cust-tag" key={c}>
                      {c}
                    </span>
                  ))}
                </div>
                <div className="muted">
                  {tq.cases} {tq.cases === 1 ? 'case' : 'cases'}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}

const AREA_CHIPS = ['critical', 'high', 'medium', 'low']

function AreaRow({ label, counts }) {
  return (
    <div className="area-row">
      <span className="area-row-label">{label}</span>
      {AREA_CHIPS.map((c) => (
        <span
          key={c}
          className={`area-chip chip-lvl-${c}${counts[c] ? '' : ' zero'}`}
          title={`${counts[c]} ${SEV_EN[c].toLowerCase()}`}
        >
          {counts[c]}
        </span>
      ))}
    </div>
  )
}

/** Red while a critical finding is open, amber for high, green when nothing is
 *  open - decided from the open counts, not from a score. */
function areaTone(a) {
  if (a.open_by.critical) return 'danger'
  if (a.open_by.high) return 'accent'
  return 'ok'
}

function AreaCard({ area, days }) {
  const tone = areaTone(area)
  const open = AREA_CHIPS.filter((c) => area.open_by[c]).map((c) => `${area.open_by[c]} ${c}`)
  return (
    <a className={`area-card area-${tone}`} href={`#/findings/${area.id}`} title={area.about}>
      <div className="area-head">
        <h3>{area.name}</h3>
        <span className="area-open" title={open.length ? `Open: ${open.join(', ')}` : 'Nothing open'}>
          {fmtNum(area.open)}
        </span>
      </div>
      <AreaRow label="New" counts={area.new} />
      <AreaRow label="Total" counts={area.total} />
      <Spark values={area.trend} days={days} />
    </a>
  )
}

/** Findings first seen per day as an area under a line. Plain SVG, no chart
 *  library (nothing fetched at runtime, like the attack graph). Each card is
 *  scaled to its own peak - the card says how many, the line says when. */
function Spark({ values, days }) {
  const W = 100
  const H = 30
  const peak = Math.max(0, ...values)
  if (!values.length || peak === 0) {
    return (
      <svg className="spark spark-flat" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-hidden="true">
        <line x1="0" y1={H - 1} x2={W} y2={H - 1} />
      </svg>
    )
  }
  const v = values.length === 1 ? [values[0], values[0]] : values
  const step = W / (v.length - 1)
  const line = v.map((n, i) => `${(i * step).toFixed(1)},${(H - 2 - (n / peak) * (H - 6)).toFixed(1)}`).join(' ')
  const at = values.indexOf(peak)
  return (
    <svg
      className="spark"
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={`peak ${peak} findings first seen on ${days[at]}`}
    >
      <title>{`Peak: ${peak} finding${peak === 1 ? '' : 's'} first seen on ${days[at]}`}</title>
      <polygon className="spark-fill" points={`0,${H} ${line} ${W},${H}`} />
      <polyline className="spark-line" points={line} />
    </svg>
  )
}

function Kpi({ label, value, sub, chip, chipTone, tone }) {
  return (
    <div className={`kpi kpi-${tone}`}>
      <div className="kpi-head">
        <span>{label}</span>
        {chip && <span className={`kpi-chip chip-${chipTone}`}>{chip}</span>}
      </div>
      <div className="kpi-value">{value}</div>
      <div className="kpi-sub">{sub}</div>
    </div>
  )
}

function SeverityBars({ counts }) {
  const max = Math.max(1, ...SEVS.map((s) => counts[s] || 0))
  return (
    <div className="sev-bars">
      {SEVS.map((s) => (
        <div className="sev-bar-row" key={s}>
          <span>{SEV_EN[s]}</span>
          <span className="sev-track">
            <span className={`sev-fill fill-${s}`} style={{ width: `${((counts[s] || 0) / max) * 100}%` }} />
          </span>
          <span className="mono">{counts[s] || 0}</span>
        </div>
      ))}
    </div>
  )
}

/** Stacked by each case's highest severity. Plain divs, no chart library -
 *  the same rule as the attack graph: nothing fetched, nothing to load. */
function DailyChart({ days }) {
  const keys = ['critical', 'high', 'medium', 'low', 'none', 'pending']
  const total = (d) => keys.reduce((n, k) => n + (d[k] || 0), 0)
  const max = Math.max(1, ...days.map(total))
  return (
    <>
      <div className="chart">
        {days.map((d) => (
          <div className="chart-col" key={d.date} title={`${d.date}: ${total(d)} cases`}>
            <div className="chart-stack">
              {keys.map((k) =>
                d[k] ? (
                  <span key={k} className={`fill-${k}`} style={{ height: `${(d[k] / max) * 100}%` }} />
                ) : null,
              )}
            </div>
            <div className="chart-label mono">{Number(d.date.slice(8))}</div>
          </div>
        ))}
      </div>
      <div className="chart-legend">
        {SEVS.map((s) => (
          <span key={s}>
            <i className={`fill-${s}`} /> {SEV_EN[s]}
          </span>
        ))}
      </div>
    </>
  )
}
