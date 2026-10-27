import { useCallback, useEffect, useState } from 'react'
import { getOverview } from '../api.js'
import { ago, fmtNum, fmtTime, shortTs } from '../format.js'
import {
  AreaCard, Badge, BigTotal, FactTiles, IconTile, Section, SummaryCard, TotalRow,
} from '../components/cards.jsx'

const POLL_MS = 15000
const SEVS = ['critical', 'high', 'medium', 'low']
const SEV_EN = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None' }
const SEV_TONE = { critical: 'danger', high: 'warn', medium: 'info', low: 'muted' }
const ROLE_EN = { sources: 'source', destinations: 'destination', accounts: 'account' }
const ROLE_ICON = { sources: 'server', destinations: 'globe', accounts: 'user' }

/** The Overview, redesigned 2026-10-19 at the user's request and laid out like
 *  SOCRadar's report since 2026-10-27 (CLAUDE.md). It answers three
 *  questions in this order: what is waiting for me (the attention row), how are
 *  we doing (the summary card, the detection areas, severity, top affected)
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
  const openBy = (s) => data.areas.reduce((n, a) => n + (a.open_by[s] || 0), 0)
  const highestOpen = SEVS.find((s) => openBy(s) > 0)
  const areasOpen = data.areas.filter((a) => a.open > 0).length
  const createdTotal = data.findings_daily.reduce((n, d) => n + (d.critical || 0) + (d.high || 0), 0)
  const sevAll = SEVS.reduce((n, s) => n + sevTotals[s], 0)

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

      <SummaryCard
        label="Summary"
        side={
          <BigTotal
            icon="shield-alert"
            tone={t.open_findings ? SEV_TONE[highestOpen] || 'muted' : 'ok'}
            label="Open findings"
            value={fmtNum(t.open_findings)}
            badge={
              t.open_findings ? (
                <Badge tone={SEV_TONE[highestOpen] || 'muted'}>Highest: {SEV_EN[highestOpen] || '—'}</Badge>
              ) : (
                <Badge tone="ok">Nothing open</Badge>
              )
            }
          >
            <TotalRow label="Mean time to contain"
                      title={`created → Contained, true positives · target ≤ ${t.mttc_target_hours} h`}>
              <span className={mttcHours != null && mttcHours > t.mttc_target_hours ? 'sev-critical' : ''}>
                {mttcHours == null ? '—' : fmtHours(mttcHours)}
              </span>{' '}
              <span className="muted">/ {t.mttc_target_hours} h</span>
            </TotalRow>
            <TotalRow label="Open cases">{fmtNum(t.open_cases)}</TotalRow>
            <TotalRow label="Customers">{fmtNum(t.customers)}</TotalRow>
          </BigTotal>
        }
      >
        <FactTiles
          facts={[
            { label: 'Last upload', value: <span className="mono">{t.last_upload ? shortTs(fmtTime(t.last_upload)) : '—'}</span>,
              title: t.last_upload ? fmtTime(t.last_upload) : undefined },
            { label: 'Cases processed', value: <><strong>{fmtNum(t.ready)}</strong> of {fmtNum(t.cases)}</> },
            { label: 'Areas with open findings',
              value: <><strong>{areasOpen}</strong> of {data.areas.length} areas</> },
          ]}
        />
        <div>
          <div className="ui-kicker">Findings created per day</div>
          <div className="ui-headline">
            <strong>{fmtNum(createdTotal)}</strong>
            high and critical, when they entered the workflow · last {data.findings_daily.length} days
          </div>
          <DailyChart days={data.findings_daily} unit="findings" keys={['critical', 'high']} />
        </div>
      </SummaryCard>

      <section aria-label="Detection areas">
        <div className="area-title">
          <h2 className="section-h">Detection areas</h2>
          <span className="muted">open workflow findings · trend of findings first seen per day of event time</span>
        </div>
        <div className="ui-area-grid">
          {data.areas.map((a) => (
            <OverviewArea key={a.id} area={a} days={data.trend_days} scope={scope} openTotal={t.open_findings} />
          ))}
        </div>
      </section>

      <div className="ov-row">
        <div className="panel ov-panel">
          <h2>Severity breakdown</h2>
          <div className="ui-section-sub">{fmtNum(sevAll)} findings by Sigma level, every case in scope</div>
          <SeverityBreakdown counts={sevTotals} total={sevAll} />
        </div>
        <div className="panel ov-panel">
          <h2>Top affected hosts &amp; accounts</h2>
          <div className="ui-section-sub">ranked by accumulated risk, per customer</div>
          {!data.top_entities.length && <div className="empty">No findings yet</div>}
          <div className="ov-top">
            {data.top_entities.map((e) => (
              <div className="ov-top-row" key={`${e.customer}|${e.role}|${e.entity}`}>
                <IconTile icon={ROLE_ICON[e.role] || 'server'} tone="info" />
                <div className="ov-top-main">
                  <div className="mono ov-top-entity" title={e.entity}>{e.entity}</div>
                  <div className="cell-sub">
                    {ROLE_EN[e.role] || e.role} <span className="cust-tag cust-tag-after">{e.customer}</span>
                  </div>
                </div>
                <span className="muted">{e.cases} {e.cases === 1 ? 'case' : 'cases'}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <Section
        icon="alert"
        tone={t.open_findings ? 'danger' : 'ok'}
        title="Most urgent findings"
        sub="Workflow findings not yet resolved - worst severity first, unassigned before assigned"
        stats={[
          { label: 'Open', value: fmtNum(t.open_findings), tone: t.open_findings ? 'danger' : 'text' },
          { label: 'Critical unassigned', value: fmtNum(t.critical_unassigned),
            tone: t.critical_unassigned ? 'danger' : 'text' },
        ]}
      >
        {!data.urgent.length ? (
          <div className="empty">Nothing is open in the workflow</div>
        ) : (
          <div className="table-scroll">
            <table className="ui-rows">
              <thead>
                <tr><th>#</th><th>Finding</th><th>Severity</th><th>Status</th></tr>
              </thead>
              <tbody>
                {data.urgent.map((r, i) => (
                  <tr key={`${r.case_id}|${r.key}`}>
                    <td className="ui-n">{i + 1}</td>
                    <td>
                      <div className="ui-main">
                        <a className="table-link mono" href={`#/finding/${r.case_id}/${encodeURIComponent(r.key)}`}>
                          {r.fd}
                        </a>{' '}
                        · {r.name}
                      </div>
                      <div className="ui-sub">
                        <span className="mono">{r.host}</span> · {r.company_name} · {r.log_type}
                      </div>
                    </td>
                    <td><span className={`sev-tag sev-tag-${r.level}`}>{SEV_EN[r.level]}</span></td>
                    <td>
                      {r.status}
                      <div className={r.assignee ? 'ui-sub' : 'ui-sub urgent-unassigned'}>{r.assignee || 'unassigned'}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="ui-section-more">
          <a href={`#/findings${scope ? `/${scope.slice(1)}` : ''}`} className="table-link">
            All open findings →
          </a>
        </div>
      </Section>

      <Section
        icon="clock"
        tone="info"
        title="Recent activity"
        sub="Uploads, processing and analyst decisions"
        stats={[{ label: 'Latest', value: data.recent.length ? ago(data.recent[0].ts) : '—' }]}
      >
        {!data.recent.length ? (
          <div className="empty">Nothing yet</div>
        ) : (
          <ul className="activity ov-activity-list">
            {data.recent.slice(0, 5).map((r, i) => (
              <li key={i} className={`act-${r.level || 'muted'}`}>
                <a href={`#/case/${r.case_id}`}>{r.text}</a>
                {r.customer && <span className="cust-tag cust-tag-after">{r.customer}</span>}
                <div className="mono muted">{ago(r.ts)}</div>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </section>
  )
}

function fmtHours(h) {
  if (h < 1) return `${Math.max(1, Math.round(h * 60))} min`
  return `${h.toFixed(1)} h`
}

/** Red while a critical finding is open, amber for high, grey and dimmed when
 *  nothing is open - decided from the open counts, not from a score. The line
 *  under the number names the open ones by level, and what the area holds in
 *  all when none is open. */
function OverviewArea({ area, days, scope, openTotal }) {
  const tone = area.open_by.critical ? 'danger' : area.open_by.high ? 'warn' : area.open ? 'info' : 'muted'
  const open = SEVS.filter((s) => area.open_by[s]).map((s) => `${area.open_by[s]} ${s}`)
  const all = SEVS.reduce((n, s) => n + (area.total[s] || 0), 0)
  const share = openTotal ? Math.round((area.open / openTotal) * 100) : 0
  return (
    <AreaCard
      href={`#/findings/area=${area.id}&status=open${scope}`}
      title={area.about}
      icon={area.id}
      tone={tone}
      value={fmtNum(area.open)}
      name={area.name}
      share={area.open ? share : 0}
      foot={area.open ? `${share}% of open · ${open.join(', ')}` : `Nothing open · ${fmtNum(all)} in all`}
      extra={<Spark values={area.trend} days={days} />}
      dim={!area.open}
    />
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

/** Each level's count, then one bar split by share - every level that has
 *  findings keeps at least a sliver, so a lone critical is never invisible. */
function SeverityBreakdown({ counts, total }) {
  const pct = (s) => (total ? Math.round(((counts[s] || 0) / total) * 100) : 0)
  return (
    <>
      <div className="ov-sev-counts">
        {SEVS.map((s) => (
          <div key={s} className={`tone-${SEV_TONE[s]}`}>
            <div className="ov-sev-n">{fmtNum(counts[s])}</div>
            <div className="ov-sev-label"><i className={`fill-${s}`} />{SEV_EN[s]}</div>
          </div>
        ))}
      </div>
      <div className="ov-sev-bar" role="img"
           aria-label={SEVS.map((s) => `${counts[s] || 0} ${s}`).join(', ')}>
        {total === 0 && <span className="fill-pending" style={{ flexGrow: 1 }} />}
        {SEVS.filter((s) => counts[s]).map((s) => (
          <span key={s} className={`fill-${s}`} style={{ flexGrow: counts[s], minWidth: 6 }} />
        ))}
      </div>
      <div className="ov-sev-pcts mono">
        {SEVS.map((s) => <span key={s}>{pct(s)}% {s}</span>)}
      </div>
    </>
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
