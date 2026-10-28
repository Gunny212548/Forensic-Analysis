import { useCallback, useEffect, useState } from 'react'
import { getOverview } from '../api.js'
import { ago, fmtNum, shortTs } from '../format.js'
import {
  AreaCard, Badge, BigTotal, IconTile, Section, StatTile, SummaryCard, TotalRow,
} from '../components/cards.jsx'

const POLL_MS = 15000
const SEVS = ['critical', 'high', 'medium', 'low']
const SEV_EN = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Informational', none: 'None' }
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
  const firstSeen = data.trend_days.map((d, i) => data.areas.reduce((n, a) => n + (a.trend[i] || 0), 0))
  const decided = t.reviewable - t.unreviewed
  const sevBadge = t.unreviewed ? (
    <Badge tone={SEV_TONE[highest] || 'muted'}>Highest: {SEV_EN[highest] || '—'}</Badge>
  ) : (
    <Badge tone="ok">{t.reviewable ? 'All decided' : 'Nothing suggested'}</Badge>
  )

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

      {/* Every customer at once: the three figures the user asked to see first (2026-10-28) -
          cases open, suggestions to review, customers. They leave the summary card here, so
          each is said once; scoped to one customer the card keeps them. */}
      {!data.company_id && (
        <div className="ui-stat-grid ov-stats">
          <StatTile icon="cases" tone={t.open_cases ? 'danger' : 'ok'} value={fmtNum(t.open_cases)}
                    label={`Open cases of ${fmtNum(t.cases)}`}
                    title="Cases with a suggestion the analyst has not decided yet" />
          <StatTile icon="shield-alert" tone={t.unreviewed ? SEV_TONE[highest] || 'muted' : 'ok'}
                    value={fmtNum(t.unreviewed)} label="To review"
                    title="Suggestions the analyst has not decided yet, in every case" />
          <StatTile icon="customers" tone="info" value={fmtNum(t.customers)} label="Customers" />
        </div>
      )}

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

      {/* All customers: each customer's overview and nothing more (the user, 2026-10-28:
          "ภาพรวมของแต่ละ Customer ไม่ต้องแสดงรายละเอียดต่างๆ"). Every detail below is on the
          customer's own Overview, which a row opens. */}
      {!data.company_id && (
        <ByCustomer rows={data.by_customer || []} areas={data.areas} coverage={data.coverage || []} />
      )}

      {data.company_id && (
        <>
          <SummaryCard
            label="Summary"
            side={
              <BigTotal
                icon="shield-alert"
                tone={t.unreviewed ? SEV_TONE[highest] || 'muted' : 'ok'}
                label="Suggestions not decided"
                value={fmtNum(t.unreviewed)}
                badge={sevBadge}
              >
                <TotalRow label="Analyst decided">
                  {fmtNum(decided)} / {fmtNum(t.reviewable)}
                </TotalRow>
                {/* No mean time to contain since 2026-10-27: nothing on screen contains a
                    finding any more (the Respond step went, gotcha #54). A case is open while a
                    suggestion in it is not decided. */}
                <TotalRow label="Open cases" title="cases with a suggestion not decided yet">{fmtNum(t.open_cases)}</TotalRow>
                <TotalRow label="Customers">{fmtNum(t.customers)}</TotalRow>
              </BigTotal>
            }
          >
            {/* No fact tiles (the user, 2026-10-28): the last upload and the files processed
                are on the line under the title, and the area cards say which areas hold
                suggestions. */}
            <FirstSeen days={data.trend_days} values={firstSeen} />
          </SummaryCard>

          <Coverage rows={data.coverage || []} attention={data.attention_files || []} />

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

          <Tactics tactics={data.tactics || []} />

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

          <TopRules rules={data.top_rules || []} />

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
        </>
      )}
    </section>
  )
}

/** One row per customer, counted as the summary card and the area cards count:
 *  suggestions not decided of all of them, the worst one not decided, cases open
 *  (a suggestion not decided) of the customer's cases, and every suggestion per
 *  detection area, then the evidence it rests on: each log source and the period
 *  it covers, and the days without an event when there are any. Worst first, as on
 *  the Customers page; a row opens that customer's own Overview. */
function ByCustomer({ rows, areas, coverage }) {
  const areaName = Object.fromEntries(areas.map((a) => [a.id, a.name]))
  return (
    <Section icon="customers" tone="info" title="By customer"
             sub="Each customer's own suggestions - open one for its whole Overview">
      {!rows.length ? (
        <div className="empty">No customer yet</div>
      ) : (
        <div className="table-scroll">
          <table className="ui-rows">
            <thead>
              <tr><th>#</th><th>Customer</th><th>Not decided</th><th>Highest not decided</th><th>Open cases</th>
                <th>Evidence</th></tr>
            </thead>
            <tbody>
              {rows.map((r, i) => {
                const parts = Object.entries(r.areas).map(([id, n]) => `${areaName[id] || id} ${fmtNum(n)}`)
                const sources = coverage.filter((c) => c.company_id === r.company_id && c.product !== null)
                return (
                  <tr key={r.company_id || 'none'}>
                    <td className="ui-n">{i + 1}</td>
                    <td>
                      <div className="ui-main">
                        {r.company_id ? (
                          <a className="table-link" href={`#/dashboard/${encodeURIComponent(r.company_id)}`}>{r.name}</a>
                        ) : (
                          r.name
                        )}
                      </div>
                      <div className="ui-sub">
                        {parts.length ? parts.join(' · ') : r.cases ? 'Nothing suggested' : 'No case uploaded'}
                      </div>
                    </td>
                    <td className="ui-count">
                      <strong>{fmtNum(r.unreviewed)}</strong> / {fmtNum(r.reviewable)}
                    </td>
                    <td>
                      {r.highest ? (
                        <span className={`sev-tag sev-tag-${r.highest}`}>{SEV_EN[r.highest] || r.highest}</span>
                      ) : (
                        <span className="muted">{r.reviewable ? 'All decided' : '—'}</span>
                      )}
                    </td>
                    <td className="ui-count">
                      {fmtNum(r.open_cases)} / {fmtNum(r.cases)}
                    </td>
                    <td>
                      {sources.length ? (
                        sources.map((c) => (
                          <div key={c.product} className="ov-evidence">
                            <div>{c.product_name}</div>
                            <div className="ui-sub mono">{coveragePeriod(c)}</div>
                            {c.gap_days > 0 && (
                              <div className="ui-sub tone-warn ov-gap">
                                {fmtNum(c.gap_days)} {c.gap_days === 1 ? 'day' : 'days'} without events
                              </div>
                            )}
                          </div>
                        ))
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  )
}

/** A log source's period: first to last day, or the times within one day. */
function coveragePeriod(r) {
  const [d0, t0] = r.first.split(' ')
  const [d1, t1] = r.last.split(' ')
  return d0 === d1 ? `${d0} ${t0.slice(0, 5)} → ${t1.slice(0, 5)}` : `${d0} → ${d1}`
}

/** What each customer's evidence covers, per log source: its files, the first and
 *  last event, how many days between them hold an event and the gaps - a quiet day
 *  can be a log not collected (NIST SP 800-92 §2.3), so it is read before trusting
 *  one. Under it, every file whose reading needs attention (the Ingest step's test). */
function Coverage({ rows, attention }) {
  const gaps = (r) => {
    if (!r.gap_days) return 'none'
    const g = r.longest_gap
    return `${fmtNum(r.gap_days)} ${r.gap_days === 1 ? 'day' : 'days'}, longest ${g.days} (${g.from} → ${g.to})`
  }
  return (
    <Section icon="cases" tone="info" title="Evidence coverage"
             sub="What each customer's evidence covers, per log source - read it before trusting a quiet period">
      {!rows.length ? (
        <div className="empty">No customer yet</div>
      ) : (
        <div className="table-scroll">
          <table className="ui-rows">
            <thead>
              <tr><th>#</th><th>Customer</th><th>Log source</th><th>Files</th><th>Period</th>
                <th>Days with events</th><th>Days without</th></tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={`${r.company_id}|${r.product}`}>
                  <td className="ui-n">{i + 1}</td>
                  <td className="ui-main">
                    {r.company_id ? (
                      <a className="table-link" href={`#/dashboard/${encodeURIComponent(r.company_id)}`}>{r.customer}</a>
                    ) : (
                      r.customer
                    )}
                  </td>
                  {r.product === null ? (
                    <td colSpan={5} className="muted">{r.cases ? 'Nothing read yet' : 'No case uploaded'}</td>
                  ) : (
                    <>
                      <td>{r.product_name}</td>
                      <td className="ui-count">{fmtNum(r.files)}</td>
                      <td className="ui-count">{coveragePeriod(r)}</td>
                      <td className="ui-count">{fmtNum(r.days)} of {fmtNum(r.span_days)}</td>
                      <td className={r.gap_days ? 'tone-warn ov-gap' : 'muted'}>{gaps(r)}</td>
                    </>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="ui-section-more">
        {!attention.length ? (
          <span className="muted">Every file was read as its log source documents it</span>
        ) : (
          <ul className="ov-attn-files">
            {attention.slice(0, 10).map((a, i) => (
              <li key={i}>
                <a className="table-link" href={`#/case/${a.case_id}/ingest`}>{a.file}</a>
                <span className="cust-tag cust-tag-after">{a.customer}</span> - {a.reason}
              </li>
            ))}
            {attention.length > 10 && <li className="muted">and {fmtNum(attention.length - 10)} more</li>}
          </ul>
        )}
      </div>
    </Section>
  )
}

/** Every ATT&CK Enterprise tactic in ATT&CK's order, as chevrons: the suggestions
 *  whose techniques reach it and the customers they are in, grey where nothing did -
 *  how far the attacks got at a glance. Order is ATT&CK's, not the order things
 *  happened (that is each case's Attack timeline). */
function Tactics({ tactics }) {
  const reached = tactics.filter((t) => t.suggestions).length
  return (
    <Section icon="lateral-movement" tone={reached ? 'danger' : 'muted'} title="ATT&CK tactics reached"
             sub="Suggestions per tactic, every case in scope - one suggestion can reach more than one">
      <div className="ov-tactics" role="list">
        {tactics.map((t) => (
          <div key={t.id} role="listitem" className={`ov-tactic${t.suggestions ? ' ov-tactic-on' : ''}`}
               title={`${t.name} (${t.ta})${t.customers.length ? ` - ${t.customers.join(', ')}` : ' - not seen'}`}>
            <span className="ov-tactic-name">{t.name}</span>
            <span className="ov-tactic-n">{t.suggestions ? fmtNum(t.suggestions) : '·'}</span>
            <span className="ov-tactic-sub">{t.customers.join(', ')}</span>
          </div>
        ))}
      </div>
    </Section>
  )
}

/** The rules that suggested most, with what the analysts decided of their
 *  suggestions - a rule whose suggestions are mostly rejected is one to re-tune.
 *  A rule opens the case holding most of its suggestions, on Attack events. */
function TopRules({ rules }) {
  return (
    <Section icon="findings" tone="info" title="Top rules"
             sub="The rules that suggested most, and what analysts decided - many rejected is a rule worth re-tuning">
      {!rules.length ? (
        <div className="empty">Nothing suggested yet</div>
      ) : (
        <div className="table-scroll">
          <table className="ui-rows">
            <thead>
              <tr><th>#</th><th>Rule</th><th>Suggestions</th><th title="accepted or modified">Accepted</th>
                <th>Rejected</th><th>Not decided</th></tr>
            </thead>
            <tbody>
              {rules.map((r, i) => (
                <tr key={r.rid}>
                  <td className="ui-n">{i + 1}</td>
                  <td>
                    <div className="ui-main">
                      <a className="table-link mono" href={`#/case/${r.case_id}/attack-events`}>{r.rid}</a> · {r.label}
                    </div>
                    <div className="ui-sub">{r.customers.join(', ')}</div>
                  </td>
                  <td className="ui-count"><strong>{fmtNum(r.suggestions)}</strong></td>
                  <td className="ui-count">{fmtNum(r.accepted + r.modified)}</td>
                  <td className={`ui-count${r.rejected ? ' tone-warn ov-gap' : ''}`}>{fmtNum(r.rejected)}</td>
                  <td className="ui-count">{fmtNum(r.undecided)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Section>
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
