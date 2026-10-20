import { useCallback, useEffect, useState } from 'react'
import { getOverview } from '../api.js'
import { ago, fmtNum } from '../format.js'

const POLL_MS = 15000
const SEVS = ['critical', 'high', 'medium', 'low']
const SEV_EN = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None' }
const ROLE_EN = { sources: 'source', destinations: 'destination', accounts: 'account' }

/** The Overview, redesigned 2026-10-19 at the user's request. It answers three
 *  questions in this order: what is waiting for me (the attention row), how are
 *  we doing (the four KPIs, the detection areas, findings per day and severity)
 *  and what do I open next (the most urgent findings, recent activity).
 *
 *  Every figure comes from GET /api/overview - never a placeholder - and every
 *  tile that counts something links to where it can be worked. What used to be
 *  here and now lives elsewhere: the findings table is the Findings page, the
 *  case list is Customers, the ATT&CK technique list is waiting for its own page. */
export default function Overview({ companyId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

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

  if (error && !data) return <div className="panel empty">Could not load the overview: {error}</div>
  if (!data) return <div className="empty">Loading...</div>

  const t = data.totals
  const scoped = (data.customer_options || []).find((c) => c.company_id === data.company_id)
  const sevTotals = Object.fromEntries(
    SEVS.map((s) => [s, data.areas.reduce((n, a) => n + (a.total[s] || 0), 0)]),
  )
  // Drill-downs keep the customer this page is scoped to.
  const scope = data.company_id ? `&company_id=${encodeURIComponent(data.company_id)}` : ''
  const todo = [
    { n: t.critical_unassigned, label: 'critical findings unassigned',
      href: `#/findings/severity=critical&unassigned=1${scope}` },
    { n: t.awaiting_review, label: 'awaiting review', href: data.review_case ? `#/case/${data.review_case}/attack-events` : '#/cases' },
    { n: t.failed_cases, label: 'cases failed', href: data.failed_case ? `#/case/${data.failed_case}/ingest` : '#/cases' },
    { n: data.attention.length, label: 'evidence problems',
      href: data.attention.length ? `#/case/${data.attention[0].case_id}/ingest` : '#/cases' },
  ].filter((x) => x.n > 0)
  // Red when it is a critical finding nobody owns, a failed case or tampered evidence;
  // a review backlog alone is only a nudge.
  const bad = t.critical_unassigned > 0 || t.failed_cases > 0 || data.attention.length > 0
  const mttcHours = t.mttc_seconds == null ? null : t.mttc_seconds / 3600

  return (
    <section className="page ov">
      <div className="top-bar">
        <div>
          <h1>Security Operations Overview</h1>
          <div className="subtitle">
            <span className="live-dot" />{' '}
            {t.last_upload ? `Last upload ${ago(t.last_upload)}` : 'No upload yet'} · {t.ready} of {t.cases}{' '}
            {t.cases === 1 ? 'file' : 'files'} processed · updated {ago(data.generated_at)}
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

      {/* Only when something is waiting: a thin banner of links, and nothing at all
          when there is nothing to do. */}
      {todo.length > 0 && (
        <div className={`attn-banner${bad ? ' attn-bad' : ''}`}>
          {todo.map((x) => (
            <a key={x.label} href={x.href}>
              <strong>{fmtNum(x.n)}</strong> {x.label}
            </a>
          ))}
        </div>
      )}
      {data.attention.length > 0 && (
        <ul className="attn-alert" role="alert">
          {data.attention.slice(0, 5).map((a) => (
            <li key={`${a.case_id}|${a.reason}`}>
              <a href={`#/case/${a.case_id}/ingest`}>{a.file}</a> <span className="cust-tag">{a.customer}</span> - {a.reason}
            </li>
          ))}
        </ul>
      )}

      <div className="stats">
        <Stat label="Open findings" value={fmtNum(t.open_findings)} tone={t.open_findings ? 'danger' : ''} />
        <Stat label="Mean time to contain" value={mttcHours == null ? '—' : fmtHours(mttcHours)}
          tone={mttcHours != null && mttcHours > t.mttc_target_hours ? 'danger' : ''}
          title={`created → Contained, true positives · target ≤ ${t.mttc_target_hours} h`} />
        <Stat label="Open cases" value={fmtNum(t.open_cases)} />
        <Stat label="Customers" value={t.customers} />
      </div>

      <div>
        <h2 className="section-h">Detection areas</h2>
        <div className="area-grid">
          {data.areas.map((a) => (
            <AreaCard key={a.id} area={a} days={data.trend_days} scope={scope} />
          ))}
        </div>
      </div>

      <div className="ov-row">
        <div className="panel ov-chart-panel">
          <h2>
            Findings created per day <span className="muted">high and critical, when they entered the workflow</span>
          </h2>
          <DailyChart days={data.findings_daily} unit="findings" keys={['critical', 'high']} />
        </div>
        <div className="panel ov-side">
          <h2>Severity distribution</h2>
          <SeverityBars counts={sevTotals} />
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

      <div className="ov-row">
        <div className="panel">
          <div className="area-title">
            <h2>Most urgent findings</h2>
            <a href={`#/findings${scope ? `/${scope.slice(1)}` : ''}`} className="table-link">
              All findings →
            </a>
          </div>
          {!data.urgent.length && <div className="empty">Nothing is open in the workflow</div>}
          <ul className="urgent">
            {data.urgent.map((r) => (
              <li key={`${r.case_id}|${r.key}`}>
                <a className="table-link mono" href={`#/finding/${r.case_id}/${encodeURIComponent(r.key)}`}>
                  {r.fd}
                </a>
                <span className={`sev-tag sev-tag-${r.level}`}>{SEV_EN[r.level]}</span>
                <span className="urgent-main">
                  {r.name} <span className="mono muted">{r.host}</span>
                  <span className="cell-sub">
                    {r.company_name} · {r.log_type} · {r.status}
                  </span>
                </span>
                <span className={r.assignee ? 'muted' : 'urgent-unassigned'}>{r.assignee || 'unassigned'}</span>
              </li>
            ))}
          </ul>
        </div>
        <div className="panel ov-activity">
          <h2>Recent activity</h2>
          {!data.recent.length && <div className="empty">Nothing yet</div>}
          <ul className="activity">
            {data.recent.slice(0, 5).map((r, i) => (
              <li key={i} className={`act-${r.level || 'muted'}`}>
                <a href={`#/case/${r.case_id}`}>{r.text}</a>
                {r.customer && <span className="cust-tag cust-tag-after">{r.customer}</span>}
                <div className="mono muted">{ago(r.ts)}</div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  )
}

function fmtHours(h) {
  if (h < 1) return `${Math.max(1, Math.round(h * 60))} min`
  return `${h.toFixed(1)} h`
}

function Stat({ label, value, tone, title }) {
  return (
    <div className="stat" title={title}>
      <div className={`stat-value${tone ? ` tone-${tone}` : ''}`}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}

const AREA_CHIPS = ['critical', 'high', 'medium', 'low']

function AreaChips({ counts, totals }) {
  return (
    <div className="area-row">
      {AREA_CHIPS.map((c) => (
        <span
          key={c}
          className={`area-chip chip-lvl-${c}${counts[c] ? '' : ' zero'}`}
          title={`${counts[c]} open of ${totals[c]} ${SEV_EN[c].toLowerCase()}`}
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

function AreaCard({ area, days, scope }) {
  const tone = areaTone(area)
  const open = AREA_CHIPS.filter((c) => area.open_by[c]).map((c) => `${area.open_by[c]} ${c}`)
  return (
    <a className={`area-card area-${tone}`} href={`#/findings/area=${area.id}&status=open${scope}`} title={area.about}>
      <div className="area-head">
        <h3>{area.name}</h3>
        <span className="area-open" title={open.length ? `Open: ${open.join(', ')}` : 'Nothing open'}>
          {fmtNum(area.open)}
        </span>
      </div>
      <AreaChips counts={area.open_by} totals={area.total} />
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

/** Stacked by severity. Plain divs, no chart library - the same rule as the
 *  attack graph: nothing fetched, nothing to load. */
function DailyChart({ days, unit, keys }) {
  const total = (d) => keys.reduce((n, k) => n + (d[k] || 0), 0)
  const max = Math.max(1, ...days.map(total))
  return (
    <>
      <div className="chart">
        {days.map((d) => (
          <div className="chart-col" key={d.date} title={`${d.date}: ${total(d)} ${unit}`}>
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
        {keys.map((s) => (
          <span key={s}>
            <i className={`fill-${s}`} /> {SEV_EN[s]}
          </span>
        ))}
      </div>
    </>
  )
}
