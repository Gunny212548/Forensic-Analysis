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
  const reviewedPct = t.reviewable ? Math.round(((t.reviewable - t.unreviewed) / t.reviewable) * 100) : 0
  const scoped = (data.customer_options || []).find((c) => c.company_id === data.company_id)
  const sevTotals = Object.fromEntries(
    SEVS.map((s) => [s, data.areas.reduce((n, a) => n + (a.total[s] || 0), 0)]),
  )
  const trend = t.created_last7 - t.created_prev7
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

      <div className="attn-row">
        <div className="attn-grid">
          <Attn
            label="Critical, unassigned"
            value={t.critical_unassigned}
            href="#/findings/severity=critical&unassigned=1"
            bad
            hint="Open critical findings nobody owns yet"
          />
          <Attn
            label="Findings awaiting review"
            value={t.unreviewed}
            href={data.review_case ? `#/result/${data.review_case}` : null}
            hint={
              data.review_case
                ? `of ${fmtNum(t.reviewable)} - opens the case with the most`
                : 'Every finding has a decision'
            }
          />
          <Attn
            label="Cases that failed"
            value={t.failed_cases}
            href="#/customers"
            bad
            hint="Processing stopped - see the case for the reason"
          />
          <Attn
            label="Evidence or audit-log problems"
            value={data.attention.length}
            href={data.attention.length ? `#/result/${data.attention[0].case_id}` : null}
            bad
            hint="A custody chain or decision history that no longer verifies"
          />
        </div>
        {data.attention.length > 0 && (
          <ul className="attn-alert" role="alert">
            {data.attention.slice(0, 5).map((a) => (
              <li key={`${a.case_id}|${a.reason}`}>
                <a href={`#/result/${a.case_id}`}>{a.file}</a> <span className="cust-tag">{a.customer}</span> - {a.reason}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="kpis">
        <Kpi
          label="Open findings"
          value={fmtNum(t.open_findings)}
          chip={`${t.created_last7} created in 7 days`}
          chipTone={trend > 0 ? 'danger' : 'ok'}
          sub={
            `high and critical, not yet Resolved · previous 7 days: ${t.created_prev7}` +
            (t.new_findings ? ` · ${fmtNum(t.new_findings)} not started` : '')
          }
          tone="danger"
        />
        <Kpi
          label="Mean time to contain"
          value={mttcHours == null ? '—' : fmtHours(mttcHours)}
          chip={t.mttc_n ? `${t.mttc_n} contained` : null}
          chipTone={mttcHours != null && mttcHours > t.mttc_target_hours ? 'danger' : 'ok'}
          sub={
            mttcHours == null
              ? `no contained true positive yet · target ≤ ${t.mttc_target_hours} h`
              : `created → Contained, true positives · target ≤ ${t.mttc_target_hours} h`
          }
          tone={mttcHours != null && mttcHours > t.mttc_target_hours ? 'danger' : 'ok'}
        />
        <Kpi
          label="Open cases"
          value={fmtNum(t.open_cases)}
          chip={t.uploaded_today ? `+${t.uploaded_today} today` : null}
          chipTone="danger"
          sub={`of ${t.cases} cases · ${reviewedPct}% of findings reviewed`}
          tone="warn"
        />
        <Kpi
          label="Customers"
          value={t.customers}
          sub={`${t.customers_with_cases} with cases`}
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
            <a href="#/findings" className="table-link">
              All findings →
            </a>
          </div>
          {!data.urgent.length && <div className="empty">Nothing is open in the workflow</div>}
          <ul className="urgent">
            {data.urgent.map((r) => (
              <li key={`${r.case_id}|${r.key}`}>
                <a className="table-link mono" href={`#/result/${r.case_id}/${encodeURIComponent(r.key)}`}>
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
                <a href={`#/result/${r.case_id}`}>{r.text}</a>
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

/** One thing waiting for the analyst. Red while it is more than zero and bad
 *  news; a link only when there is somewhere to go. */
function Attn({ label, value, href, bad, hint }) {
  const tone = value ? (bad ? 'danger' : 'accent') : 'ok'
  const body = (
    <>
      <span className="attn-value">{fmtNum(value)}</span>
      <span className="attn-label">{label}</span>
    </>
  )
  return href && value ? (
    <a className={`attn attn-${tone}`} href={href} title={hint}>
      {body}
    </a>
  ) : (
    <div className={`attn attn-${tone}`} title={hint}>
      {body}
    </div>
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
