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
    { n: t.critical_undecided, label: 'critical findings not decided',
      href: `#/findings/severity=critical&decision=Unreviewed${scope}` },
    { n: t.failed_cases, label: 'cases failed', href: data.failed_case ? `#/case/${data.failed_case}/ingest` : '#/cases' },
    { n: data.attention.length, label: 'evidence problems',
      href: data.attention.length ? `#/case/${data.attention[0].case_id}/ingest` : '#/cases' },
  ].filter((x) => x.n > 0)
  // Red when it is a critical finding nobody has decided, a failed case or tampered evidence.
  const bad = t.critical_undecided > 0 || t.failed_cases > 0 || data.attention.length > 0
  // Counted as the case page counts (the user, 2026-10-27: the Overview must match
  // what a case shows): every suggestion, and the ones the analyst has not decided.
  // The high / critical findings (FD ids) are listed on their own below, most urgent first.
  const sevAll = SEVS.reduce((n, s) => n + sevTotals[s], 0)
  const highest = SEVS.find((s) => sevTotals[s] > 0)
  const areasHit = data.areas.filter((a) => SEVS.some((s) => a.total[s])).length
  const firstSeen = data.trend_days.map((d, i) => data.areas.reduce((n, a) => n + (a.trend[i] || 0), 0))

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
            tone={t.unreviewed ? SEV_TONE[highest] || 'muted' : 'ok'}
            label="Suggestions not decided"
            value={fmtNum(t.unreviewed)}
            badge={
              t.unreviewed ? (
                <Badge tone={SEV_TONE[highest] || 'muted'}>Highest: {SEV_EN[highest] || '—'}</Badge>
              ) : (
                <Badge tone="ok">{t.reviewable ? 'All decided' : 'Nothing suggested'}</Badge>
              )
            }
          >
            <TotalRow label="Analyst decided">
              {fmtNum(t.reviewable - t.unreviewed)} / {fmtNum(t.reviewable)}
            </TotalRow>
            {/* No mean time to contain since 2026-10-27: nothing on screen contains a
                finding any more (the Respond step went, gotcha #54). A case is open while a
                suggestion in it is not decided. */}
            <TotalRow label="Open cases" title="cases with a suggestion not decided yet">{fmtNum(t.open_cases)}</TotalRow>
            <TotalRow label="Customers">{fmtNum(t.customers)}</TotalRow>
          </BigTotal>
        }
      >
        <FactTiles
          facts={[
            { label: 'Last upload', value: <span className="mono">{t.last_upload ? shortTs(fmtTime(t.last_upload)) : '—'}</span>,
              title: t.last_upload ? fmtTime(t.last_upload) : undefined },
            { label: 'Cases processed', value: <><strong>{fmtNum(t.ready)}</strong> of {fmtNum(t.cases)}</> },
            { label: 'Areas with suggestions',
              value: <><strong>{areasHit}</strong> of {data.areas.length} areas</> },
          ]}
        />
        <FirstSeen days={data.trend_days} values={firstSeen} />
      </SummaryCard>

      <section aria-label="Detection areas">
        <div className="area-title">
          <h2 className="section-h">Detection areas</h2>
          <span className="muted">every suggestion, as each case counts it · trend of suggestions first seen per day of event time</span>
        </div>
        <div className="ui-area-grid">
          {data.areas.map((a) => (
            <OverviewArea key={a.id} area={a} days={data.trend_days} all={sevAll} />
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
                  {e.role === 'accounts' && (
                    <>
                      <SeenOn label="on" items={e.hosts || []} short={(h) => h.split('.')[0]}
                              empty="computer not recorded in its events" />
                      <SeenOn label="from" items={e.sources || []} empty="source address not recorded in its events" />
                    </>
                  )}
                </div>
                <span className="muted">{e.cases} {e.cases === 1 ? 'case' : 'cases'}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <Section
        icon="alert"
        tone={t.awaiting_review ? 'danger' : 'ok'}
        title="Most urgent findings"
        sub="High and critical findings not decided yet - worst first, then the one waiting longest"
        stats={[
          { label: 'Not decided', value: fmtNum(t.awaiting_review), tone: t.awaiting_review ? 'danger' : 'text' },
          { label: 'Critical not decided', value: fmtNum(t.critical_undecided),
            tone: t.critical_undecided ? 'danger' : 'text' },
        ]}
      >
        {!data.urgent.length ? (
          <div className="empty">Every high and critical finding is decided</div>
        ) : (
          <div className="table-scroll">
            <table className="ui-rows">
              <thead>
                <tr><th>#</th><th>Finding</th><th>Severity</th><th>First event</th></tr>
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
                    <td className="mono muted">{shortTs(r.detected)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="ui-section-more">
          <a href={`#/findings/decision=Unreviewed${scope}`} className="table-link">
            All findings not decided →
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

/** Every suggestion in the area, as the case page's Attack events counts it: the
 *  number is all of them, the line under it their levels and how many the analyst
 *  has not decided. Coloured by
 *  the worst level the area holds, grey and dimmed when it holds nothing. It
 *  opens the case holding most of them, on Attack events. */
function OverviewArea({ area, days, all }) {
  const n = SEVS.reduce((k, s) => k + (area.total[s] || 0), 0)
  const worst = SEVS.find((s) => area.total[s])
  const levels = SEVS.filter((s) => area.total[s]).map((s) => `${fmtNum(area.total[s])} ${s}`)
  const foot = !n
    ? 'Nothing suggested'
    : `${levels.join(', ')} · ${area.undecided ? `${fmtNum(area.undecided)} not decided` : 'all decided'}`
  return (
    <AreaCard
      href={area.case_id ? `#/case/${area.case_id}/attack-events` : undefined}
      title={area.cases > 1 ? `${area.about} - in ${area.cases} cases; opens the one with the most` : area.about}
      icon={area.id}
      tone={SEV_TONE[worst] || 'muted'}
      value={fmtNum(n)}
      name={area.name}
      share={all ? Math.round((n / all) * 100) : 0}
      foot={foot}
      extra={<Spark values={area.trend} days={days} />}
      dim={!n}
    />
  )
}

/** Suggestions by the day their first event happened, every area added up -
 *  the same measure and span as the case page's chart, on the area cards'
 *  shared axis. Plain SVG (nothing fetched). */
function FirstSeen({ days, values }) {
  if (!days.length) return null
  const W = 900
  const H = 110
  const peak = Math.max(1, ...values)
  const x = (i) => (days.length === 1 ? W / 2 : (i * W) / (days.length - 1))
  const line = values.map((v, i) => `${x(i).toFixed(1)},${(H - 4 - (v / peak) * (H - 12)).toFixed(1)}`).join(' ')
  const at = values.indexOf(Math.max(...values))
  return (
    <div>
      <div className="ui-kicker">Suggestions by the day their first event happened</div>
      <div className="ui-headline">
        <strong>{fmtNum(values.reduce((a, b) => a + b, 0))}</strong>
        from {days[0]} to {days[days.length - 1]} · most on {days[at]} ({values[at]})
      </div>
      <svg className="case-firstseen" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img"
           aria-label={`Suggestions per day of first event, most on ${days[at]} with ${values[at]}`}>
        <polygon points={`${x(0)},${H} ${line} ${x(days.length - 1)},${H}`} />
        <polyline points={line} />
      </svg>
      <div className="case-firstseen-axis mono">
        <span>{days[0]}</span>
        {days.length > 2 && <span>{days[Math.floor(days.length / 2)]}</span>}
        {days.length > 1 && <span>{days[days.length - 1]}</span>}
      </div>
    </div>
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

/** Where an account was seen, one line each (the user, 2026-10-27: SYSTEM or a local
 *  Administrator is a different account on each computer): "on" the computers whose
 *  logs hold its flagged events, "from" the addresses they came from - most events
 *  first, three shown (a computer by its short name), the rest counted, every full
 *  value on hover. */
function SeenOn({ label, items, empty, short = (v) => v }) {
  if (!items.length) return <div className="cell-sub ov-seen-on">{empty}</div>
  const all = items.map(([v, n]) => `${v} (${fmtNum(n)} events)`).join('\n')
  return (
    <div className="cell-sub ov-seen-on" title={all}>
      {label}{' '}
      {items.slice(0, 3).map(([v, n], i) => (
        <span key={v}>
          {i > 0 && ' · '}
          <span className="mono">{short(v)}</span> ({fmtNum(n)})
        </span>
      ))}
      {items.length > 3 && ` +${items.length - 3} more`}
    </div>
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
